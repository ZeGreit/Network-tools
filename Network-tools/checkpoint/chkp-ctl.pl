#!/usr/bin/perl

use lib qw(/opt/app/network/perl/modules/lib/perl5);
use Net::SSL;
use Config::Simple;
use Data::Dumper;
use Net::DNS();
use Data::Validate::IP qw(is_ipv4 is_innet_ipv4);
use Data::IPV4::Range::Parse qw(parse_ipv4_cidr);
use Getopt::Long qw(:config no_ignore_case);
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use lib dirname(abs_path($0));
use lib::APIsession;
use lib::APIsearch;
use lib::APIwrite;

$ENV{PERL_NET_HTTPS_SSL_SOCKET_CLASS} = 'Net::SSL';
$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

my $workdir = $ENV{HOME};
my $scrdir = dirname(abs_path($0));
my $cfg = "$scrdir/chkp.cfg";
my $sidfile = "$workdir/.chkp-API-sid";
my $sid;
my @string1;
my $string2;
my $string3;
my @string4;
my @string5;
my $string6;
my $string7;
my @string8;
my $string9;
my $string10;
my $string11;
my $string12;
my $string13;
my $string14;
my $string15;
my $debug;
my $printsid;
my $noP;
my $logout;
my $login;
my $nat;

my $userid = getpwuid ($<);
if ($userid eq 'root'){
    print "$I User $userid is not allowed to run this script\n";
    exit 1;
}

my $chkp_cfg = new Config::Simple($cfg);
if ( ! -f $cfg ){print "Config file chkp.cfg wa not found. Exiting...\n";exit 1;}

my $server = $chkp_cfg->param('checkpoint.host');
my $rw_usr = $chkp_cfg->param('checkpoint.rw_user');
my $rw_psw = $chkp_cfg->param('checkpoint.rw_pass');
my $id = { "user" => "$rw_usr", "password" => "$rw_psw" };

if ( ! $ARGV[0] || "$ARGV[0]" eq "-h" ){
    usage($0);
}


sub session_check {
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

    if ( $printsid ){print "sid: $sid\n\n";}
}

GetOptions('-a=s{1,}' => \@string1,
	   '--discard' => \$string3,
	   '-g=s{1,}' => \@string4,
	   '-grem=s{1,}' => \@string15,
	   '-sg=s{1,}' => \@string8,
	   '-s=s{1,}' => \@string5,
	   '-r' => \$string7,
	   '-e' => \$string10,
	   '--net=s' => \$string11,
	   '--host=s' => \$string12,
	   '--comm=s' => \$string13,
	   '-as' => \$string9,
	   '--nat' => \$nat,
	   '-f=s' => \$rulefile,
	   '--publish' => \$string2,
	   '--install=s' => \$string14,
	   '--no-progress' => \$noP,
	   '--sid' => \$printsid,
	   '-d' => \$debug,
	   '-login' => \$login,
	   '-logout' => \$logout);

if ( !$logout ){
    session_check;
}

if ( $string14 ){
    my $string = lc $string14;
    my $targets;
    my $policy;
    if ( $string !~ /^fw.*/ ){
	$targets = get_gw($string14, $server, $sid, $debug);
	if (scalar (@$targets) < 1){print "Specified policy has no installation targets. Exiting...\n";exit 1;}
	$policy = $string14;
    }
    else{
	my $target = $string14;
        ($policy, undef, undef) = show_gateway($sid, $server, $target, $debug);
        print "Specified gateway was not found. Exiting...\n" and exit 1 unless $policy;
	push @$targets, $string14;
    }
    install_policy($sid, $server, $targets, $policy, $debug, $noP);
    logout_api($server, $sid);
    exit;
}

if ( $string10 ){
    unless ($string11 or $string12){print "Object type not specified. Exiting...\n";exit 1;}
    unless ($string13){print "The field that is edited must be specified. Exiting...\n";exit 1;}
    my $objtype;
    my $objname;
    my $fieldname;
    my $field;
    $objtype = "network" and $objname = $string11 if $string11;
    $objtype = "host" and $objname = $string12 if $string12; 
    $fieldname = "comments" and $field = $string13 if $string13;
    
    set_obj($sid, $server, $objtype, $objname, $fieldname, $field, $debug); 
    exit;
}

if ( @string1 ){ 
    if ( scalar (@string1) > 3 ){print "Too many arguments. Exiting...\n";exit 1;}
    my $ip;
    my $mask;
    my $comment;
    my $name;
    my $addr;
    if ( @string1[0] =~ /^([0-9]+\.){3}[0-9]+$/ ){
	$addr = @string1[0];
	print "Invalid IP address specified. Exiting...\n" and exit 1 unless is_ipv4($addr);
	print "Too many arguments. Exiting...\n" and exit 1 if @string1[2];
	$comment = @string1[1];
	$name = R_NSlookup($addr);
	if ( ! $name ){$name = "ip-$addr";}
    }else{
	$name = @string1[0];
	$addr = @string1[1];
	$comment = @string1[2];
    }
    if ( $addr =~ /\// ){
	my $slashes = () = $addr =~ m/[\/]/g;
	if ( $slashes > 1 ){print "Invalid network address $addr format. Exiting...\n";exit 1;}
	$ip = $addr;
	$mask = $addr;
	$ip =~ s/\/.*$//;
	$mask =~ s/^.*\///;
	if ( ! is_ipv4($ip) ){print "Invalid IP address part $ip. Exiting...\n";exit 1;}
	unless ( $mask =~ /^[0-9]+$/ ){print "Invalid mask $mask format. Exiting...\n";exit 1;}
	if ( $mask > 32 ){print "Invalid mask length $mask. Exiting...\n";exit 1;}
    }else{
	$ip = $addr;
	if ( ! is_ipv4($ip) ){print "Invalid IP address $ip. Exiting...\n";exit 1;}
    }
    if ( $name =~ /^[0-9]+/ ){print "Invalid symbol at the start of object name $name. Exiting...\n";exit 1;}
    add_host($sid, $server, $name, $ip, $mask, $comment, $debug);
}

if ( $string2 || $string3 ){
    my $changes = show_session($sid, $server);
    my $op;
    if ( $string3 ){$op = "discard";}
    if ( $string2 ){$op = "publish";}
    if ( $changes > 0 ){
	pub_dis($sid, $server, $op, $debug, $noP);
    }else{
	print " No changes made - nothing to $op\n\n";
    }
    exit;
}

if ( @string8 ){
    my $members;
    my $proto;
    my $port;
    my $gname = @string8[0];
    if ( scalar(@string8) > 1 ){
	for my $i (1..$#string8){
	    my $member = @string8[$i];
	    my $colons = () = $member =~ m/[:]/g;
	    if ( $colons > 1 ){print "Invalid service $member format. Skipping...\n";next;}
	    if ( $colons == 1 ){
		$proto = $member;
    		$port = $member;
    		$proto =~ s/:.*$//;
    		print "Valid protocols are tcp and udp. Skipping...\n" and next unless $proto =~ /(^tcp$|^udp$)/;
    		$port =~ s/^.*://;
	    }
	    my ($service) = get_service($sid, $server, $member, $proto, $port, $debug);
	    
	    my $objname = @$service[0]->{'name'};
	    
	    foreach (@$service){
		my $timeout = $_->{'st'};
		if ( $timeout == 3600 ){$objname = $_->{'name'};}
	    }
	    
	    if ( $objname ){push @$members, $objname;}
	    else{print "Object $member was not found. Skipping...\nUse \"-s\" option to create the object\n\n";}
	}
    }
    my $type = "service";
    my ($old, undef, undef) = get_group($sid, $server, $gname, $debug, $type);
    set_group($sid, $server, $gname, $members, $old, $debug, $type, undef);
}

if ( @string4 || @string15 ){
    my $members;
    my $network;
    my $removal;
    if ( @string15 ){
	$removal = "true";
	@string4 = @string15;
    }
    my $gname = @string4[0];
    if ( scalar(@string4) > 1 ){
	for my $i (1..$#string4){
	    my $member = @string4[$i];
	    if ( $member =~ /^([0-9]+\.){3}[0-9]{1,3}\/.{1,2}$/ ){$network = "true";}
	    my ($objname, $ip, $subnet, $type) = get_objname($sid, $server, $member, $debug, $network);
	    if ( $objname ){push @$members, $objname;}
	    else{print "Failed to add object $member to group $gname. Reason - not found. Skipping...\nUse \"-a\" option to create the object\n\n";}
	}
    }
    my ($old, undef, undef) = get_group($sid, $server, $gname, $debug, undef);
    set_group($sid, $server, $gname, $members, $old, $debug, undef, $removal);
}

if ( @string5 && scalar (@string5) > 0 ){
     my $proto;
     my $port;
     my $name;
     if ( scalar (@string5) > 2 ){print "Too many arguments. Exiting...\n";exit 1;}
     if ( scalar (@string5) == 1 ){
        my $colons = () = @string5[0] =~ m/[:]/g;
	if ( $colons > 1 ){print "Invalid service format. Exiting...\n";exit 1;}
        $proto = @string5[0];
        $port = @string5[0];
        $proto =~ s/:.*$//;
        $proto =~ s/(^.*$)/\L\1/g;
        print "Valid protocols are tcp and udp. Exiting...\n" and exit 1 unless $proto =~ /(^tcp$|^udp$)/;
        $port =~ s/^.*://;
#        print "Invalid port range\n" and exit unless $port =~ /^[0-9]+$/;
#        print "Invalid port range\n" and exit if $port > 65535;
        $name = "$proto-$port";
    }else{
	my $colons = () = @string5[1] =~ m/[:]/g;
	if ( $colons > 1 ){print "Invalid service format. Exiting...\n";exit 1;}
	$name = @string5[0];
	$proto = @string5[1];
        $port = @string5[1];
        $proto =~ s/:.*$//;
        $proto =~ s/(^.*$)/\L\1/g;
        print "Valid protocols are tcp and udp. Exiting...\n" and exit 1 unless $proto =~ /(^tcp$|^udp$)/;
        $port =~ s/^.*://;
#        print "Invalid port range\n" and exit unless $port =~ /^[0-9]+$/;
#        print "Invalid port range\n" and exit if $port > 65535;
    }
    add_service($sid, $server, $name, $proto, $port, $debug);
}

if ( $string7 ){
    if ( ! -f $rulefile ){print "The file $rulefile not found. Exiting...\n";exit 1;}
    add_rule($sid, $server, $rulefile, $debug, $nat);
    exit;
}

if ( $string9 ){
    if ( ! -f $rulefile ){print "The file $rulefile not found. Exiting...\n";exit 1;}
    add_section($sid, $server, $rulefile, $debug);
    exit;
}

if ( $logout ){
    if ( -f "$sidfile" ){
        open my $sfile, "$sidfile";
        my $shash;
        while (<$sfile>){
            chomp;
            my ($key, $val) = split /=/;
            $shash->{$key} = $val;
        }
        $sid = $shash->{'sid'};
        if ( $printsid ){print "sid: $sid\n\n";}
        $sid = check_sid($server, $sid);
        if ($sid) {
            logout_api($server, $sid);
        }
        else {
            print "No logout required\n";
        }
    }
}

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

sub R_NSlookup {
    my $res = Net::DNS::Resolver->new;
    my $name_server = 'IPofDNSserver'; # TO DO: add more DNS servers for redundancy
    my $addr = shift;
    my $reverse = join( '.', reverse( split /\./, $addr)) . '.in-addr.arpa';
    $res->nameservers($name_server);
    my $query = $res->query($reverse, "PTR");
    my $result;
    if ($query) {
        foreach my $rr ($query->answer) {
            next unless $rr->type eq "PTR";
            return $rr->{'ptrdname'}->{'label'}[0];
        }
    }
    else {
        return 0;
    }
}

sub usage {
    print "\nusage: $0 <options> <arguments>\n\n";
    print "Write options: \n\n";
    print "-h                                           : this (help) message\n";
    print "--sid                                        : print session ID\n";
    print "-d                                           : additionally print unprocessed JSON output from web API\n";
    print "-a [<name>] <IP>[/<mask>] [comment]          : add host or network type object, if name is not specified - nslookup is performed or (if nslookup is unsuccessful) ip-<ip address> format is used.\n";
    print "-g <name> [<member>[ <member>[...]]]         : add existing object(s) to a group, if the group does not exist - it is created\n";
    print "-grem <name> [<member>[ <member>[...]]]      : remove existing object(s) from a group\n";
    print "-sg <gname> [<member>[ <member>[...]]]       : add existing objects to a service group, if the group does not exist - it is created\n";    
    print "-s [<name>] <protocol>:<port>                : add a service type of object (currently tcp or udp), if name is not specified it is made\n";
    print "                                             : from protocol and port (protocol-port)\n";
    print "-e --<objtype> <name> --<fieldname> <value>  : edit object's specific parameter. Valid objtypes are \"host\", \"net\". Valid fieldnames are \"comm\"\n";    
    print "-r [--nat] -f <filename>                     : add rules from the JSON formatted file, use option \"--nat\" for adding NAT rules\n";    
    print "-as -f <filename>                            : add access section(s) to access policy(ies) from file with a format \"layer|section name|position\" (double quotes are not needed)\n";        
    print "--publish [--no-progress]                    : publish the changes made in current session to SDM\n";    
    print "--discard [--no-progress]                    : discard the changes made in current session\n";
    print "--install <gateway>|<policy> [--no-progress] : install assigned policy on a specified gateway, optionally \"--no-progress\" does not display the progress bar - only returns task ID\n";
    exit;
};
