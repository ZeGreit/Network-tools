#!/usr/bin/perl

use lib qw(/opt/app/network/perl/modules/lib/perl5);
#use Net::SSL;
use Config::Simple;
use Data::Dumper;
use MIME::Base64;
use Data::Validate::IP qw(is_ipv4 is_innet_ipv4);
use Getopt::Long qw(:config no_ignore_case);
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use lib dirname(abs_path($0));
use lib::APIsession;
use lib::APIsearch;
use lib::APIwrite;

#$ENV{PERL_NET_HTTPS_SSL_SOCKET_CLASS} = 'Net::SSL';
$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

my $workdir = dirname(abs_path($0));
my $sidfile = "$workdir/.sid";
my $cfg = "$workdir/chkp.cfg";
my $netfile = "$workdir/networks";
my $grpfile = "$workdir/groups";
my $sgrpfile = "$workdir/svcgroups";
my $srangefile = "$workdir/svcrange";
my $empty = {};
my $sid;
my @string1;
my $string2;
my $string3;
my $string4;
my $string5;
my $string6;
my $string7;
my $string8;
my $string9;
my $string10;
my $string11;
my $string12;
my $string13;
my $string14;
my $string15;
my @string16;
my $nonets;
my $objname;
my $type;
my $verbose;
my $debug;
my $limit;
my $brief;
my $printsid;
my $newversion;

my $chkp_cfg = new Config::Simple($cfg);
if ( ! -f $cfg ){print "Config file chkp.cfg was not found. Exiting...\n";exit;}

my $server = $chkp_cfg->param('checkpoint.host');
my $ro_usr = $chkp_cfg->param('checkpoint.ro_user');
my $ro_psw = $chkp_cfg->param('checkpoint.ro_pass');
my $id = { "user" => "$ro_usr", "password" => "$ro_psw" };

if ( ! $ARGV[0] || "$ARGV[0]" eq "-h" ){
    usage($0);
}

GetOptions('-cli=s{2}' => \@string1,
	   '-a=s' => \$string2,
	   '-i=s' => \$string4,
	   '-L=s' => \$string3,	   
	   '-g=s' => \$string5,
	   '-s=s' => \$string6,
	   '-R=s' => \$string7,
	   '-p' => \$string8,
	   '-N' => \$string10,
	   '-G' => \$string11,
	   '-S' => \$string12,
	   '-t=s' => \$string9,	   
	   '-f' => \$string14,
	   '-gw=s' => \$string13,
	   '-pkg=s' => \$string15,
	   '--fw=s{3}' => \@string16,
	   '-v' => \$verbose,
	   '-d' => \$debug,
	   '-b' => \$brief,
	   '-nv' => \$newversion,
	   '--sid' => \$printsid,
	   '--no-nets' => \$nonets,
	   '-l=i' => \$limit);

$sid = get_sid($server, $id, $sidfile) unless @string1;
if ( $printsid  ){print "Session Id: $sid \n\n";}

if ( $string14 ){
    if ( not $string15 and not $string13 ){print "Package or gateway name not specified. Exiting...\n";exit;}
    
    my $stringtype;
    my $src;
    my $dst;
    my $svc;
    my $ip;
    my $proto;
    my $port;
    my $src_list;
    my $dst_list;
    my $svc_list;
    my $policy;
    
    if ( $string13 ){
	chomp($string13);
	($policy, undef, undef) = show_gateway($sid, $server, $string13, $debug);
	unless ( $policy ){print "Policy not found for specified gateway. Exiting...\n";exit;} 
    }else{
	chomp($string15);
	$policy = $string15;
    }

    if ( @string16 ){
	$src = @string16[0];
	$dst = @string16[1];
	$svc = @string16[2];
	$port = $svc;
	$proto = $svc;
	$proto =~ s/:.*$//;
	$port =~ s/^.*://;                
    
	if ( $src =~ m/^([0-9]+\.){3}[0-9]+$/ ){$stringtype = check_ip($src);}
	else{print "Invalid source IP address. Exiting...\n";exit;}
	if ( "$stringtype" eq "invalid" ){
	    print "IP address format detected but the IP address is invalid. Exiting...\n";
	    exit;
	}
    
	if ( $dst =~ m/^([0-9]+\.){3}[0-9]+$/ ){$stringtype = check_ip($dst);}
	else{print "Invalid destination IP address. Exiting...\n";exit;}
	if ( "$stringtype" eq "invalid" ){
	    print "IP address format detected but the IP address is invalid. Exiting...\n";
	    exit;
	}

    	$src_list = search_obj_by_ip($sid, $server, $src, $debug, $limit, undef);
    	$dst_list = search_obj_by_ip($sid, $server, $dst, $debug, $limit, undef);        
        
	my $services = get_service($sid, $server, undef, $proto, $port, $debug);

	foreach (@$services){
	    push @$svc_list, $_->{'name'}; 
	}
	
	my @types = ( "service-tcp", "service-udp" );
	my $svc_ranges;
	foreach(@types){
	    my (undef, $srange) = get_sranges($sid, $server, $_, $limit, $debug);
	    push(@$svc_ranges, @$srange);
	}
	
	$svc_list = get_range_obj($svc_list, $svc_ranges, $proto, $port);
    
	$svc_list = get_objects_list($svc_list, undef, undef, $brief, undef, $limit, undef, "service") if scalar(grep $_, @$svc_list) > 0;
    }

    check_flow($sid, $server, $policy, $src_list, $dst_list, $svc_list, $debug);
    exit;
}

if ( $string2 || $string4 ){
    my $types;
    my $network;
    chomp($string2);
    chomp($string4);
    
    if ( $string2 =~ /^([0-9]+\.){3}[0-9]{1,3}\/.{1,2}$/ ){$network = "true";}
    if ( $string4 =~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/.{1,2}$/ ){$network = "true";}
    if ( $string4 ){
	if ( $network ){@$types = ( "network" );}
	else{@$types = ( "host", "network" );}
	foreach (@$types){search_object($sid, $server, undef, $string4, $verbose, $debug, $limit, $network, $_);}
    }else{search_object($sid, $server, $string2, undef, $verbose, $debug, $limit, $network, undef);}
    exit;
}

if ( $string7 ){
    chomp($string7);
    show_rule($sid, $server, $string7, $debug);
    exit;
}

if ( $string13 and not $string14){
    chomp($string13);
    my ($policy, $type, $interfaces) = show_gateway($sid, $server, $string13, $debug);
    print "$type: $string13\n";
    print "Policy installed: ", $policy, "\n";
    if ( scalar (grep $_, @$interfaces) > 0 ){
	print "\n Interfaces:\n";
	foreach (@$interfaces){
	    print "  $_->{'ifname'}|$_->{'ip'}|/$_->{'mask'}\n";
	}
    }
    exit;
}

if ( $string10 ){
    chomp($string10);
    my ($count, $networks) = get_networks($sid, $server, $limit, $debug);
    open (FILE, '>', "$netfile");
    foreach (@$networks){
	print FILE "$_->{'name'}|$_->{'network'}\n";
    }
    close FILE;
        print "\n Total networks: $count \n";
    exit;
}

if ( $string11 ){
    chomp($string11);
    my ($count, $groups) = get_groups($sid, $server, $limit, $debug);
    open (FILE, '>', "$grpfile");
    foreach (@$groups){
	print FILE "$_->{'name'}|$_->{'member'}\n";
    }
    close FILE;
        print "\n Total groups: $count \n";
    exit;
}

if ( $string12 ){
    chomp($string12);
    my ($count, $sgroups) = get_sgroups($sid, $server, $limit, $debug);
    open (FILE, '>', "$sgrpfile");
    foreach (@$sgroups){
	print FILE "$_->{'name'}|$_->{'member'}\n";
    }
    close FILE;
        print "\n Total service groups: $count \n";
    exit;
}

if ( $string8 and not $string14){
    chomp($string8);
    show_packages($sid, $server, $debug);
    exit;
}

if ( $string9 ){
    chomp($string9);
    my ($task_name, $status, $progress, undef) = show_task($sid, $server, $string9, $debug);
    if ( $task_name ){
	print "Task-id: $string9\n Type: $task_name\n Progress: $progress%\n Status: $status\n\n";
    }else{
	print "The task \"$string9\" either does not exist or has expired\n\n";
    }
    exit;
}

if ( $string5 ){
    chomp($string5);
    my ($objname, $objtype, $members) = get_group($sid, $server, $string5, $debug, undef);
    if ( $objname ){
	print "$objtype: $objname\n";
	my $objc = scalar (grep $_, @$members);
	if ( $objc == 0 ){print "\nThe group is empty\n";}
	if ( $objc > 0 ){
	    print "\n Members($objc):\n";
	    foreach (@$members){
		my $out = " $_->{'type'}: $_->{'name'} $_->{'ip'}";
		$out =~ s/\ +/ /g;
		print $out, "\n";
	    }
	    print "\n";
	}
    }
    exit;
}

if ( $string6 ){
    chomp($string6);
    my $proto;
    my $port;
    if ( $string6 =~ /^.+:[0-9]+$/ ){
	$proto = $string6;
	$port = $string6;
	$proto =~ s/:.*$//;
	$port =~ s/^.*://;
    }
    
    my $services = get_service($sid, $server, $string6, $proto, $port, $debug);

    if ( scalar(grep $_, @$services) > 0 ){
	foreach (@$services){
	    my $out = "$_->{'type'}: $_->{'name'} (port: $_->{'pnumber'}, session-timeout: $_->{'st'})";
	    $out =~ s/\(port:\ ,\ /(/;
	    print $out, "\n";
	}
    }else {print "No service $string6 was found\n";}
    exit;
}

if ( @string1 ){
    
    my $scrdir = dirname(abs_path($0));
    my $cfg = "$scrdir/chkp.cfg";
    my $chkp_cfg = new Config::Simple($cfg);
    my $workdir = $ENV{HOME};
    my $sidfile = "$workdir/.chkp-API-sid";
    my $rw_usr = $chkp_cfg->param('checkpoint.rw_user');#new
    my $rw_psw = $chkp_cfg->param('checkpoint.rw_pass');#new
    my $id = { "user" => "$rw_usr", "password" => "$rw_psw" };#new
    my $sid = get_sid($server, $id, $sidfile);
    
    my $target = @string1[0];
    my $cmd = @string1[1];
    
#    print "\nCommand is not allowed. Exiting...\n\nList of allowed commands is:\n \"arp -a\"\n \"clish -c \\\"show route\\\"\"\n \"ip ne\"\n\n" and exit unless "$cmd" eq "arp -a" or "$cmd" eq "clish -c \"show route\"" or "$cmd" eq "ip ne";
    
    my ($encoded) = run_CLI_scr($sid, $server, $target, $cmd);
    my $decoded = decode_base64($encoded);
    print $decoded, "\n";
    pub_dis($sid, $server, "discard", $debug, 1);
    logout_api($server, $sid);
    exit;
}

if ( $string3 ){
    my $stringtype;
    my $ip;
    my $subnet;
    my $network;
    my $objects;
    chomp($string3);
    if ( $string3 =~ m/^([0-9]+\.){3}[0-9]+$/ ){$stringtype = check_ip($string3);}
    if ( "$stringtype" eq "invalid" ){
	print "IP address format detected but the IP address is invalid. Exiting...\n";
	exit;
    }

    if ( $string3 =~ /^([0-9]+\.){3}[0-9]{1,3}\/.{1,2}$/ ){$network = "true";}
    $ip = $string3 if "$stringtype" eq "valid";

    if ( $brief or not $ip ){
	($objname, $ip, $subnet, $type) = get_objname($sid, $server, $string3, $debug, $network);

	if ( $objname ){
	    push @$objects, $objname;
	}else{
	    print "The specific object \"$string3\" could not be located\n";
	    exit;
	}
    }     

    if ( $ip and not $brief ){(undef, $objects) = search_obj_by_ip($sid, $server, $ip, $debug, $limit, $nonets);}##new    
    else{$objects = get_objects_list($objects, $ip, $subnet, $brief, $nonets, $limit, $objname, $type);}
				
    my ($rule_usg, $object_usg, $nat_usg) = locate_object($sid, $server, $type, $objects, $verbose, $debug, $brief);
    if ( scalar(grep $_, @$rule_usg) > 0 ){
        print "\nUsage in access rules:\n";
        foreach (@$rule_usg){
    	    print $_, "\n";
	}
    }else{
	print "\nObject is not used in access rules\n";
    }
    if ( scalar(grep $_, @$nat_usg) > 0 ){
        print "\nUsage in NAT rules:\n";
        foreach (@$nat_usg){
    	    print $_, "\n";
	}
    }else{
	print "\nObject is not used in NAT rules\n";
    }
    if ( scalar(grep $_, @$object_usg) > 0 ){
        print "\nUsage in other objects:\n";
        foreach (@$object_usg){
    	    print "  $_->{'objname'} in $_->{'type'}: $_->{'name'}\n";
	}
    }else{
        print "\nObject is not used in other objects\n";
    }    
}
exit;

sub get_sid{
    my ($server, $id, $sidfile) = @_;

    if ( -f "$sidfile" ){
	open my $sfile, "$sidfile";
	my $shash;
	while (<$sfile>){
	    chomp;
	    my ($key, $val) = split /=/;
	    $shash->{$key} = $val;
	}
	$sid = $shash->{'sid'};
	$sid = check_sid($server, $sid);
    }
    if ( ! $sid ) {$sid = login_api($server, $id, $sidfile);}
    return $sid;
};

sub get_objects_list{
    my ($objects, $ip, $subnet, $brief, $nonets, $limit, $objname, $type) = @_;
    if ( $ip ){
        if ( $objname ){print "$type: $objname ($ip)\n";}
        unless ( $brief || $nonets ){
	    my $networks = is_ip_in_net($ip);
	    if ( scalar(grep $_, @$networks) > 0 ){
	        foreach (@$networks){
		    push @$objects, $_;
		}
	    }
	}
    }
    elsif ( $subnet ){print "$type: $objname ($subnet)\n";}
    else{print "$type: $objname $ip\n" if $objname;}
	
    unless ( $brief ){
	my $tmp_array;	
	foreach (@$objects){
	    push @$tmp_array, $_;
	}
	my $count = 0;
	$limit = 100 unless ( $limit );
	while ( scalar(grep $_, @$tmp_array) != 0 ){
	    my $tmp_array2;
		
	    foreach (@$tmp_array){
		my $grouplist;
		$grouplist = is_obj_in_group($_) unless "$type" eq "service";
		$grouplist = is_svc_in_sgroup($_) if "$type" eq "service";
		foreach (@$grouplist){push @$tmp_array2, $_;}
	    }
	    undef $tmp_array;
	    foreach (@$tmp_array2){
		push @$tmp_array, $_;
	    } 
		
	    foreach (@$tmp_array){
	        push @$objects, $_;
	    }
	    $count++;
	    if ( $count == $limit){last;}
	}
    }
    return $objects;
};

sub get_range_obj{
    my ($svc_list, $svc_ranges, $proto, $port) = @_;

    foreach(@$svc_ranges){
    	my $lowport = $_->{'port'};
	my $highport = $_->{'port'};
	my $type = $_->{'type'};
	$type =~ s/^.*-//;
	$lowport =~ s/-.*$//;
	$highport =~ s/^.*-//;
    	if ( "$proto" eq "$type" ){
	    if ( $port > $lowport and $port < $highport ){
	    	push(@$svc_list, $_->{'name'});
	    }
	}
    }
    return $svc_list;
}

sub is_svc_in_sgroup {
    my ($obj) = @_;
    my $member;
    my $gname;
    my $groups;
    unless ( $sgrpfile ){print "Service file $sgrpfile was not found. Exiting...\n";exit;}
    open FILE, "$sgrpfile";
    while (<FILE>){
	chomp;
	($gname, $member) = split /\|/;
	push @$groups, $gname if ( "$member" eq "$obj" );
    }
    close FILE;
    return $groups;
};

sub is_obj_in_group {
    my ($obj) = @_;
    my $member;
    my $gname;
    my $groups;
    unless ( $grpfile ){print "Network file $grpfile was not found. Exiting...\n";exit;}
    open FILE, "$grpfile";
    while (<FILE>){
	chomp;
	($gname, $member) = split /\|/;
	push @$groups, $gname if ( "$member" eq "$obj" );
    }
    close FILE;
    return $groups;
};

sub is_ip_in_net {
    my ($ip) = @_;
    my $net;
    my $name;
    my $networks;
    unless ( $netfile ){print "Network file $netfile was not found. Exiting...\n";exit;}
    open FILE, "$netfile";
    while (<FILE>){
	chomp;
	($name, $net) = split /\|/;
	push @$networks, $name if ( is_innet_ipv4($ip, $net) );
    }
    close FILE;
    return $networks;
};

sub check_ip {
    my ($ip) = @_;
    my $type;
    if( is_ipv4($ip) ){
	$type = "valid";
    }else{
	$type = "invalid";
    }
    return $type;	
};

sub usage {
    print "\nusage: $0 <options> <search string>\n\n";
    print "Search options: \n\n";
    print "-h                        							: this (help) message\n";
    print "-d                        							: additionally print unprocessed JSON output from web API\n";
    print "-l <nr of lines>          							: when -i or -a option is used, limits the query to API output to specified number of matches (default is 500)\n";
    print "                          							: when used with -L, specifies the depth of indirect usage search\n";
    print "-i <IP> or <name> [-v]     							: find the host or network type object(s) by IP address or name (wildcards are also accepted)\n";
    print "                          							: if -v is specified, the search is also done in comments field\n";
    print "-a <IP> or <name> [-v]      							: find any type of object(s) by IP address or name (wildcards are also accepted)\n";
    print "                          							: if -v is specified, the search is also done in comments field\n";
    print "-L <IP> or <name> [-b] [--no-nets] [-v]    					: Locate the object by IP address or name (currently in access rules and other objects), -b does only direct usage search,\n";
    print "                          							: --no-nets does indirect search, but excludes the networks which the object belongs to,\n"; 
    print "										: if -v is specified the contents of rules are also listed\n";
    print "-f -pkg <pkg name>|-gw <gw name> [ --fw <src> <dst> <protocol>:<port> ]		: if only -pkg or -gw option is used - lists the rules of specified policy package,\n";
    print "										: --fw option checks the specified rulebase for matching flow\n";
    print "-g <group name>           							: list members of the specified group\n";
    print "-s <svc name>|<protocol:port>     						: search for service objects by name or protocol:port\n";    
    print "-R <pkg name>_<rule uid>                                  			: display contents of the specified rule\n";
    print "-p                                                       			: show policy packages\n";
    print "-t <task-id>                                             			: show task status\n";    
    print "-cli <target> \"<cmd/script>\"                     				: run the command or script on the specified device\n";
    exit;
};
