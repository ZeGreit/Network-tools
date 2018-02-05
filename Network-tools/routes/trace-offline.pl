#!/usr/bin/perl

use lib qw(/opt/app/network/perl/modules/lib/perl5);
use DBI;
use strict;
use Term::ANSIColor;

my $driver = "SQLite";
my $db_name = ':memory:';
my $dbd = "DBI:$driver:dbname=$db_name";
my $dbh = DBI->connect($dbd, { RaiseError => 1, })
                      or die $DBI::errstr;
$dbh->sqlite_backup_from_file("/opt/app/network/routes/routes.db");

my $device;
my $vrf;
my $vdc;
my $inc;
my $out;
my $subnet;
my $int;
my $vdcm;
my $vrfm;
my @d_preflist;
my @s_preflist;
my @fws;
my $left;

my $src = $ARGV[0];
my $dst = $ARGV[1];
my $proto;
my $port;
my $verb;

if ($ARGV[2] !~ "-d"){$proto = $ARGV[2]; $port = $ARGV[3];}

sub help{
    print "\nUsage: trace-offline {<src-ip>} {<dst-ip>} [<protocol>] [<port>] [-d {<device>[,<vsys>[,<vrf>]]|vpn|internet|leased|user}]\n";
    print "       trace-offline [-h|help]\n";
    print " \n";
    print " If <protocol> and <port> are specified script checks for matching policies on firewalls in path,\n";
    print " if not - only traceroute is performed.\n";
    print " \n";
    print " -d	if source IP is external or cannot be located - source router vsys and vrf (separated by \",\") can be specified as starting point,\n";
    print "        templates can be used also: vpn (starts from fwricb06), internet (starts from ruricb03 VRF-Internet), leased (starts from ruri008a),\n";
    print "        user (starts from RXRI300A sebnet-user).\n";
    print " \n";
    exit;
}

sub verbose{
    for my $param (0..$#ARGV){
	if ($ARGV[$param] =~ "-v"){$verb = "true";last;}
    }
}

sub specify_dev{
    my $dev;
    for my $param (0..$#ARGV){
	if ($ARGV[$param] =~ "-d"){$dev = "$ARGV[$param+1]";last;}
    }
    
    if ($dev =~ "vpn"){$dev = "fwricb06,Root,trust-vr"; $int = "eth1/0.103:1"; }
    if ($dev =~ "internet"){$dev = "rxri203,,VRF-Internet";}
    if ($dev =~ "leased"){$dev = "ruri008a";}
    if ($dev =~ "user"){$dev = "RXRI300A,,sebnet-user";}
    
    my @obj = split (/,/, $dev,);
    $device = "$obj[0]";
    $vdc = "$obj[1]";
    $vrf = "$obj[2]";
    if ($vrf){$vrfm = "_$vrf";}
    if ($vdc){$vdcm = "_$vdc";}
    if ($device){
        print "\n ##TRACEROUTE\n";
	print "$device$vdcm$vrfm";
	$left = "$int $device $vdc $vrf";
	undef $vdcm;
	undef $vrfm;
    }
}

sub locate_source{
    print "\n ##TRACEROUTE\n";
    my $sql = "select DEVICE,VDC,VRF,SUBNET,INTERFACE from routes2 where SUBNET = ? and NEXTHOP like '%attached%' limit 1;";
    my $stmt = $dbh->prepare($sql);
    for (my $i=32; $i>=18; $i--){
	my $net=`ipcalc -n $src/$i|sed -e 's/NETWORK\=//'`;
	chomp $net;
	my $qsub = "$net/$i";
	$stmt->execute("$qsub");
	my (@obj) = $stmt->fetchrow();
	$stmt->finish();
	
	if (@obj){
	    $device = "$obj[0]";
	    if ($device =~ "20a" || $device =~ "21a" || $device =~ "22a"){$device =~ s/ricb/stgd/;}
	    $vdc = "$obj[1]";
	    if ($vdc){$vdcm = "_$vdc";}
	    $vrf = "$obj[2]";
	    if ($vrf){$vrfm = "_$vrf";}
	    $subnet = "$obj[3]";
	    $int = "$obj[4]";
	    last;
	}
    }

    if ($device){
	if ($device =~ "^fw" || $device =~ "^RF" ){ 
	    print ">($subnet)$int   ";
	    print color("yellow"), "$device$vdcm$vrfm", color("reset");
	    $left = "$int $device $vdc $vrf";
	    undef $vdcm;
	    undef $vrfm;
	}else {
	    print ">($subnet)$int ";
	    print color("bold"), "$device$vdcm$vrfm", color("reset");
	    undef $vdcm;
	    undef $vrfm;
	}
    } 
    else {
	print "Source could not be located - exiting...\nYou can use -d option to specify source router and vrf. Check help for more info.\n";
	print " \n";
	$dbh->disconnect();
	exit;
    }
}

sub trace{
    
    for (my $i=32; $i>=1; $i--){
	    my $net=`ipcalc -n $dst/$i|sed -e 's/NETWORK\=//'`;
	    chomp $net;
	    my $qsub = "$net/$i";
	    push @d_preflist, $qsub;
	}	
	push @d_preflist, "0.0.0.0/0";
    
    my $nexthop = "some";

#    while ($nexthop !~ "attached" && $device){
while ($nexthop){
	undef $nexthop;
	my $sql = "select NEXTHOP,\"DEVICE:1\",\"VDC:1\",\"VRF:1\",INTERFACE,IF from result2 where SUBNET = ? and (DEVICE like ? and VDC like ? and VRF like ?) limit 1;";
	my $stmt = $dbh->prepare($sql);
	
	for my $prefix(@d_preflist){
	    $stmt->execute("$prefix","$device","$vdc","$vrf");
	    my (@obj) = $stmt->fetchrow();
	    $stmt->finish();
	    
	    if (@obj){
		$nexthop = "$obj[0]";
		$device = "$obj[1]";
		if ($device =~ "20a" || $device =~ "21a" || $device =~ "22a"){$device =~ s/ricb/stgd/;}
		$device =~ s/rugr008/ruri008/;
		$vdc = "$obj[2]";
		if ($vdc){$vdcm = "_$vdc";}
		$vrf = "$obj[3]";
		if ($vrf){$vrfm = "_$vrf";}
		$inc = "$obj[4]";
		$out = "$obj[5]";
		last;
	    } 
#	    if ($prefix =~ "0.0.0.0/0" && !@obj){print "\nRoute not found...\n";last;}
	}    

#	if ($nexthop !~ "attached"){
if ($nexthop){
	    if ($device =~ "^fw" || $device =~ "^RF" ){ 
		print "   >$inc \n>($nexthop)$out ";
		print color("yellow"), "  $device$vdcm$vrfm", color("reset");
		undef $vdcm;
		undef $vrfm;
	    } else{
		print "   >$inc \n>($nexthop)$out ";
		print color("bold"), "  $device$vdcm$vrfm", color("reset");
		undef $vdcm;
		undef $vrfm;
		}
	    push @fws, "$left $inc";
	    $left = "$out $device $vdc $vrf";
	}
    }
    print "\n";
}

sub fwcheck{
    
    my $szone;
    my $tmpszone;
    my $dzone;
    my $CPscr = "/opt/app/network/bin/chkp-search";
    my $SRXexpect = "/opt/app/network/routes/flowcheck/SRX-exp";
    my $NSexpect = "/opt/app/network/routes/flowcheck/NetScr-exp";
    my $outfile = "/opt/app/network/routes/flowcheck/output.tmp";
    my $user = "username";
    my $pass = "password";
    
    print "\n ##FIREWALLS##\n";

    for my $line(@fws){
	
	my @col = split (/ /, $line,);    
	$inc = "$col[0]";
	$device = "$col[1]";
	$vdc = "$col[2]";
	$vrf = "$col[3]";
	$out = "$col[4]";
	
    sub getzone{	
	
	my $sql = "select ZONE from fwzone where INTERFACE = ? and (DEVICE like ? and VDC like ? and VRF like ? ) limit 1;";
	
	my $stmt = $dbh->prepare($sql);
	
        $stmt->execute("$inc","$device","$vdc","$vrf");
	my (@obj) = $stmt->fetchrow();
	$stmt->finish();
	$szone = "$obj[0]";
	if ($device =~ "^fw" && $device !~ "^fw.*06" && $vdc !~ "02-23" && $vdc !~ "partner" && $vdc !~ "IP-Soft" && $vdc !~ "VsysCom"){$szone = "$szone-$vdc";}
	if ($vdc =~ "partner"){$szone = "$szone-vsys-$vdc";}
	if ($device =~ "^fw.*06"){$szone = "$szone-vpn"; $szone =~ s/internet/internet-ec/; }
	if ($vdc =~ "02-23"){$szone = "$szone-$vdc"; $szone =~ s/untrust-fwri/untrust-fw/; }
	
	$stmt->execute("$out","$device","$vdc","$vrf");
	my (@obj) = $stmt->fetchrow();
	$stmt->finish();
	$dzone = "$obj[0]";
	if ($device =~ "^fw" && $device !~ "^fw.*06" && $vdc !~ "02-23" && $vdc !~ "partner" && $vdc !~ "IP-Soft" && $vdc !~ "VsysCom"){$dzone = "$dzone-$vdc";}
	if ($vdc =~ "partner"){$dzone = "$dzone-vsys-$vdc";}
	if ($device =~ "^fw.*06"){$dzone = "$dzone-vpn"; $dzone =~ s/internet/internet-ec/; }
	if ($vdc =~ "02-23"){$dzone = "$dzone-$vdc"; $dzone =~ s/untrust-fwri/untrust-fw/; }

	if ($vdc =~ "VsysCom" && $dzone && !$tmpszone){$szone = "$szone-$vdc";$dzone = "$dzone-$vdc";}
	
	if ($vdc =~ "VsysCom" && !$dzone){$tmpszone = "$szone-$vdc";next;}
	if ($vdc =~ "VsysCom" && $tmpszone){
	    $szone = "$tmpszone";
	    $dzone = "$dzone-$vdc";
	    undef $tmpszone;
	}
	
	if ($device =~ "^fwpc"){
	    print "$device", "_", "$vdc:\n" if $vdc;
	    print "$device:\n" if not $vdc;	    
	    system "$CPscr -f -gw $vdc --fw $src $dst $proto:$port" if $vdc;
	    system "$CPscr -f -gw $device --fw $src $dst $proto:$port" if not $vdc;	    
	    return;
	}
	
	if ($device =~ "^RF"){
	    print "$device:  $szone -> $dzone \n";
	    system "$SRXexpect $pass $device $szone $dzone $src $dst $proto $port $user | grep -A1000 ^---- | grep -B1000 :node | grep -v :node > $outfile";
	    
	    if ($verb =~ "true"){system "cat $outfile";}
		else{
		    open my $output, $outfile;
		    while (my $line2 = <$output>){
			if ($line2 =~ /Policy:/){print $line2;}
		    }
		}
	    
	    unlink $outfile;
	    print " \n";
	}
	if ($device =~ "^fw"){
	    print "$device-$vdc:  $szone -> $dzone \n";
	    system "$NSexpect $device $user $pass $vdc $szone $dzone $src $dst > $outfile";
	    open my $output, $outfile;
	    while (my $line2 = <$output>){
		if ($line2 =~ /Action/ || $line2 =~ /enabl|disabl/){
		    print $line2;
		}
	    }
	    unlink $outfile;
	    print " \n";
	}
	undef $szone;
	undef $dzone;
    }
	
	if ($device =~ "^RF" || $device =~ "^fw"){getzone;}
    }
    print " \n";

}

verbose;
specify_dev;
if (!$src || $src =~ "-h" || $src =~ "help"){help;}
if (!$device){locate_source;}
trace;
if($proto && $port){fwcheck;}

$dbh->disconnect();
