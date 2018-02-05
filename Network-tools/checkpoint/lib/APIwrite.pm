package lib::APIwrite;

use LWP::UserAgent;
use LWP::Protocol::https;
use HTTP::Request::Common;
use JSON;
use lib::APIsearch;
use Data::Dumper;
use Time::Progress;

use strict;
#use warnings;

use Exporter qw(import);

our @EXPORT = qw(add_host set_obj set_group add_service add_rule add_section pub_dis install_policy);

sub add_section {
    my ($sid, $server, $rulefile, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $cmd = "add-access-section";
    
    open FILE, "$rulefile";
    while (<FILE>){
	chomp;
	my ($layer, $section, $position) = split /\|/;
	my $objdata = { "layer" => "$layer", "position" => "$position", "name" => "$section" };
	
	my $enter = POST(
            "https://$server/web_api/$cmd",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
	);
    
	my $access = $uasession->request($enter);
	    my $outputmsg = $access->decoded_content;
    	    my $json_join = JSON->new->utf8;
	    my $join_data = $json_join->decode($outputmsg);
	    if ( $debug ){print $outputmsg, "\n";}
    	    
    	    if ($access->is_success) {
    		print "\nLayer: $layer - $section section added to position $position\n";
    		print "\n Use \"-publish\" as an argument to publish the changes to SDM\n";
	    	print " or \"-discard\" to discard the changes\n\n";	    		
    	    }else{
    		my $msg = $join_data->{'message'};
    		my $code = $join_data->{'code'};

                if ( $msg ){print "$code: $msg\n";
	        if ( "$msg" =~ /warning/ ){
    		    my $warnings = $join_data->{'warnings'};
        	    print "\n Warning(s):\n";
        	    foreach (@$warnings){
        		print "  ", $_->{'message'}, "\n";
        	    }
    		}
    		if ( "$msg" =~ /error/ ){
        	    my $errors = $join_data->{'errors'};
        	    print "\n Error(s):\n";
        	    foreach (@$errors){
        		print "  ", $_->{'message'}, "\n";
        	    }
    		}
    		print "\n";
    		exit 1;
        	}else{
            	    print "HTTP POST error code: ", $access->code, "\n";
        	    print "HTTP POST error message: ", $access->message, "\n";
            	    die;
        	}
    	    }
    }
    exit;
};

sub add_rule {
    my ($sid, $server, $rulefile, $debug, $nat) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $cmd = "add-access-rule";
    $cmd = "add-nat-rule" if $nat;
    
    my $json_txt = do {
	open(FILE, "<:encoding(UTF-8)", $rulefile);
	local $/;
	<FILE>
    };
    
    my $objdata = JSON->new->decode($json_txt);
    my $rules = $objdata->{'rules'};
    
    foreach (@$rules){
    
	my $enter = POST(
            "https://$server/web_api/$cmd",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($_),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
	);
    
	my $access = $uasession->request($enter);
	    my $outputmsg = $access->decoded_content;
    	    my $json_join = JSON->new->utf8;
	    my $join_data = $json_join->decode($outputmsg);
	    if ( $debug ){print $outputmsg, "\n";}
    	    
    	    if ($access->is_success) {
    		my $out;
		unless ( $nat ){
		    my $source = $_->{'source'};
		    my $destination = $_->{'destination'};
		    my $service = $_->{'service'};
		
		    print "Rule added!  $_->{'layer'}: "; 
		    foreach (@$source){$out .= "$_,";}
		    $out =~ s/,$//;		
		    $out .= " -> "; 
		    foreach (@$destination){$out .= "$_,";}
		    $out =~ s/,$//;		
		    $out .= " : ";  		
		    foreach (@$service){$out .= "$_,";}
	    	    $out =~ s/,$//;
	    	}else{
	    	    print "Rule added!  $_->{'package'}: "; 
	    	    my $o_source = $join_data->{'original-source'}->{'name'};
	    	    my $o_dest = $join_data->{'original-destination'}->{'name'};
	    	    my $o_svc = $join_data->{'original-service'}->{'name'};
	    	    my $t_source = $join_data->{'translated-source'}->{'name'};
	    	    my $t_dest = $join_data->{'translated-destination'}->{'name'};
	    	    my $t_svc = $join_data->{'translated-service'}->{'name'};
	    	    my $method = $join_data->{'method'};
		    $out = "$method NAT | original ( src: $o_source, dst: $o_dest, svc: $o_svc ) | translated ( src: $t_source, dst: $t_dest, svc: $t_svc )";
	    	}	
	    	print $out, "\n";
	    	if ( \$_ == \@$rules[-1] ){
		    print "\n Use \"-publish\" as an argument to publish the changes to SDM\n";
	    	    print " or \"-discard\" to discard the changes\n\n";	    		
		}

	    }else{
    		my $msg = $join_data->{'message'};
    		my $code = $join_data->{'code'};

                if ( $msg ){print "$code: $msg\n";
	        if ( "$msg" =~ /warning/ ){
    		    my $warnings = $join_data->{'warnings'};
        	    print "\n Warning(s):\n";
        	    foreach (@$warnings){
        		print "  ", $_->{'message'}, "\n";
        	    }
    		}
    		if ( "$msg" =~ /error/ ){
        	    my $errors = $join_data->{'errors'};
        	    print "\n Error(s):\n";
        	    foreach (@$errors){
        		print "  ", $_->{'message'}, "\n";
        	    }
    		}
    		print "\n";
    		exit 1;
        	}else{
            	    print "HTTP POST error code: ", $access->code, "\n";
        	    print "HTTP POST error message: ", $access->message, "\n";
            	    die;
        	}
    	    }
    }
};

sub add_service {
    my ($sid, $server, $name, $proto, $port, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $cmd = "add-service-$proto";
    my $objdata = { "name" => "$name", "port" => "$port", "match-for-any" => "false" };
    
    my $enter = POST(
            "https://$server/web_api/$cmd",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );
    
    my $access = $uasession->request($enter);
	my $outputmsg = $access->decoded_content;
    	my $json_join = JSON->new->utf8;
        my $join_data = $json_join->decode($outputmsg);
        if ($access->is_success) {
	    if ( $debug ){print $outputmsg, "\n";}
	    print "Service $name ($proto:$port) was successfully added\n";
	    print "\n Use \"-publish\" as an argument to publish the changes to SDM\n";
	    print " or \"-discard\" to discard the changes\n\n";	    		
	}else{
    	    my $msg = $join_data->{'message'};
    	    my $code = $join_data->{'code'};

            if ( $msg ){print "$code: $msg\n";
            if ( "$msg" =~ /warning/ ){
        	my $warnings = $join_data->{'warnings'};
        	print "\n Warning(s):\n";
        	foreach (@$warnings){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    if ( "$msg" =~ /error/ ){
        	my $errors = $join_data->{'errors'};
        	print "\n Error(s):\n";
        	foreach (@$errors){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    print "\n";
    	    exit 1;
            }else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
};

sub set_group {
    my ($sid, $server, $gname, $members, $old, $debug, $svc, $removal) = @_;
    my $cmd;
    my $objdata;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $target = "group";
    my $op = "add";
    if ( $svc ){$target = "service-group";}
    
    if ( $members ){
	if ( $old ){
	    $cmd = "set-$target";
	    $op = "remove" if $removal;
	    $objdata = { "name" => "$gname", "members" => { "$op" => [ @$members ] } };
	}else{
	    $cmd = "add-$target";
	    $objdata = { "name" => "$gname", "members" => [ @$members ] };
	    print "Group does not exist. Exiting...\n\n" and exit if $removal;
	}
    }
    
    if ( ! $members ){
	print "No members specified to be removed. Exiting...\n\n" and exit if $removal;
	if ( $old ){print "The $target $gname already exist, but no members specified to be added. Exiting...\n\n";exit;}
	print "No members specified - an empty $target $gname will be created\n";
	$objdata = { "name" => "$gname" };
	$cmd = "add-$target";
    }

    my $enter = POST(
            "https://$server/web_api/$cmd",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );
    
    my $access = $uasession->request($enter);
	my $outputmsg = $access->decoded_content;
    	my $json_join = JSON->new->utf8;
        my $join_data = $json_join->decode($outputmsg);
        if ($access->is_success) {
	    if ( $debug ){print $outputmsg, "\n";}
	    if ( $old ){
		foreach (@$members){
		    print " $_ added to $target $gname\n" unless $removal;
		    print " $_ removed from $target $gname\n" if $removal;
		}
	    }else{
		print "\nNew $target $gname was created";
		if ( $members ){
		    print " with the following members:\n";
		    foreach (@$members){print " $_\n";}
		}
	    }
	    print "\n Use \"-publish\" as an argument to publish the changes to SDM\n";
	    print " or \"-discard\" to discard the changes\n\n";	    		
	}else{
    	    my $msg = $join_data->{'message'};
    	    my $code = $join_data->{'code'};

            if ( $msg ){print "$code: $msg\n";
            if ( "$msg" =~ /warning/ ){
        	my $warnings = $join_data->{'warnings'};
        	print "\n Warning(s):\n";
        	foreach (@$warnings){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    if ( "$msg" =~ /error/ ){
        	my $errors = $join_data->{'errors'};
        	print "\n Error(s):\n";
        	foreach (@$errors){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    print "\n";
    	    exit 1;
            }else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
};

sub set_obj {
    my ($sid, $server, $type, $name, $fieldname, $field, $debug) = @_;
    my $objdata = { "name" => "$name", "$fieldname" => "$field" };
    my $cmd = "set-$type";
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
        
    my $enter = POST(
            "https://$server/web_api/$cmd",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );
    
    my $access = $uasession->request($enter);
	my $outputmsg = $access->decoded_content;
    	my $json_join = JSON->new->utf8;
        my $join_data = $json_join->decode($outputmsg);
        if ($access->is_success) {
	    if ( $debug ){print $outputmsg, "\n";}
	    print "\n Field \"$fieldname\" for $type object $name was set to \"$field\" successfully\n"; 
	    print "  Use \"-publish\" as an argument to publish the changes to SDM\n";
	    print "  or \"-discard\" to discard the changes\n\n";
    	    
    	}else{
    	    my $msg = $join_data->{'message'};
    	    my $code = $join_data->{'code'};

            if ( $msg ){print "$code: $msg\n";
            if ( "$msg" =~ /warning/ ){
        	my $warnings = $join_data->{'warnings'};
        	print "\n Warning(s):\n";
        	foreach (@$warnings){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    if ( "$msg" =~ /error/ ){
        	my $errors = $join_data->{'errors'};
        	print "\n Error(s):\n";
        	foreach (@$errors){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    print "\n";
    	    exit 1;
            }else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
};

sub add_host {
    my ($sid, $server, $name, $ip, $cidr, $comment, $debug) = @_;
    my $mask;
    my $objdata;
    my $cmd;
    my $opdesc;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    
    if ( $cidr ){
	$mask = cidr_to_mask($cidr);
	$objdata = { "name" => "$name", "subnet" => "$ip", "subnet-mask" => "$mask", "comments" => "$comment" };
	$cmd = "add-network";
	$opdesc = "Network $name ($ip\/$mask) successfully added";
    }else{
	$objdata = { "name" => "$name", "ip-address" => "$ip", "comments" => "$comment" };
	$cmd = "add-host";
	$opdesc = "Host $name ($ip) successfully added";
    }
        
    my $enter = POST(
            "https://$server/web_api/$cmd",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );
    
    my $access = $uasession->request($enter);
	my $outputmsg = $access->decoded_content;
    	my $json_join = JSON->new->utf8;
        my $join_data = $json_join->decode($outputmsg);
        if ($access->is_success) {
	    if ( $debug ){print $outputmsg, "\n";}
	    print " $opdesc\n Use \"-publish\" as an argument to publish the changes to SDM\n";
	    print " or \"-discard\" to discard the changes\n\n";
    	    
    	}else{
    	    my $msg = $join_data->{'message'};
    	    my $code = $join_data->{'code'};

            if ( $msg ){print "$code: $msg\n";
            if ( "$msg" =~ /warning/ ){
        	my $warnings = $join_data->{'warnings'};
        	print "\n Warning(s):\n";
        	foreach (@$warnings){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    if ( "$msg" =~ /error/ ){
        	my $errors = $join_data->{'errors'};
        	print "\n Error(s):\n";
        	foreach (@$errors){
        	    print "  ", $_->{'message'}, "\n";
        	}
    	    }
    	    print "\n";
    	    exit 1;
            }else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
};

sub cidr_to_mask {

    my %cidr = (
	'1'	=>	'128.0.0.0',
	'2'	=>	'192.0.0.0',
	'3'	=>	'224.0.0.0',
	'4'	=>	'240.0.0.0',
	'5'	=>	'248.0.0.0',
	'6'	=>	'252.0.0.0',
	'7'	=>	'254.0.0.0',
	'8'	=>	'255.0.0.0',
	'9'	=>	'255.128.0.0',
	'10'	=>	'255.192.0.0',
	'11'	=>	'255.224.0.0',
	'12'	=>	'255.240.0.0',
	'13'	=>	'255.248.0.0',
	'14'	=>	'255.252.0.0',
	'15'	=>	'255.254.0.0',
	'16'	=>	'255.255.0.0',
	'17'	=>	'255.255.128.0',
	'18'	=>	'255.255.192.0',
	'19'	=>	'255.255.224.0',
	'20'	=>	'255.255.240.0',
	'21'	=>	'255.255.248.0',
	'22'	=>	'255.255.252.0',
	'23'	=>	'255.255.254.0',
	'24'	=>	'255.255.255.0',
	'25'	=>	'255.255.255.128',
	'26'	=>	'255.255.255.192',
	'27'	=>	'255.255.255.224',
	'28'	=>	'255.255.255.240',
	'29'	=>	'255.255.255.248',
	'30'	=>	'255.255.255.252',
	'31'	=>	'255.255.255.254',
	'32'	=>	'255.255.255.255',
    );
    return $cidr { $_[0] };
};    


sub pub_dis {
    my ($sid, $server, $op, $debug, $noP) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objdata = {};
    
    my $enter = POST(
            "https://$server/web_api/$op",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );
    
    my $access = $uasession->request($enter);
	my $outputmsg = $access->decoded_content;
    	my $json_join = JSON->new->utf8;
        my $join_data = $json_join->decode($outputmsg);
        if ($access->is_success) {
            if ( $debug ){print $outputmsg, "\n";}
            foreach (keys %$join_data){
        	my $key = $_;
        	$key =~ s/message/status/;
        	$key =~ s/-/ /g;
        	print " $key: $join_data->{$_}\n" unless $noP;
    	    }
	    return if $noP;
	    print "\n";
	    if ( "$op" eq "publish" ){
		my $progress;
		my $task_name;
		my $status = "in progress";
		my $count = 0;
		my $p = Time::Progress->new;
		$| = 1;
		
		while ( "$status" eq "in progress" ){
		    ($task_name, $status, $progress, undef) = show_task($sid, $server, $join_data->{'task-id'}, undef);
		    if ( $count == 0 ){print " Type: $task_name\n\n"}

		    my $out = ProgressB($progress);
		    print "\r$out";		    		    
		    $count++;
		    sleep (1);
		}
		print "\n Done in: ";
		$p->stop;
		if ( $p->elapsed < 61 ){print $p->elapsed, "s.\n\n";}
		else{print $p->elapsed_min, "\n";}		
	    }     	    
    	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit 1;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    	    
};

sub install_policy {
    my ($sid, $server, $targets, $package, $debug, $noP) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objdata = { "policy-package" => "$package", "access" => "true", "targets" => [ @$targets ] };
    
    my $enter = POST(
            "https://$server/web_api/install-policy",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );
    
    my $access = $uasession->request($enter);
	my $outputmsg = $access->decoded_content;
    	my $json_join = JSON->new->utf8;
        my $join_data = $json_join->decode($outputmsg);
        if ($access->is_success) {
            if ( $debug ){print $outputmsg, "\n";}
            foreach (keys %$join_data){
        	my $key = $_;
        	$key =~ s/message/status/;
        	$key =~ s/-/ /g;
        	print "$key: $join_data->{$_}\n";
    	    }
	    return if $noP;
	    print "\n";
	    my $progress;
	    my $task_name;
	    my $messages;
	    my $status = "in progress";
	    my $count = 0;
	    my $p = Time::Progress->new;
	    $| = 1;
		
	    while ( "$status" eq "in progress" ){
		($task_name, $status, $progress, $messages) = show_task($sid, $server, $join_data->{'task-id'}, undef);
		if ( $count == 0 ){print " Type: $task_name\n\n";}
		    
		my $out = ProgressB($progress);
		print "\r$out";		    		    
		$count++;
		sleep 1;
	    }
	    print "\n Done in: ";
	    $p->stop;
	    if ( $p->elapsed < 61 ){print $p->elapsed, "s.\n\n";}
	    else{print $p->elapsed_min, "\n";}
	    print "Status: $status\n";
	    if ( "$status" ne "succeeded" ){
		foreach (@$messages){
		    if ( $_->{'err'} ){
			print $_->{'err'}, "\n";
		    }
		}
	    }
	    print "\n";
    	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit 1;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }    	    
};

sub ProgressB{
    my ($progress) = @_;
    my $min = 0;
    my $max = 100;
    my $length = 40;
    my $done = $progress / $max * $length; 
    $done =~ s/\..*$//; 
    my $remaining = $length - $done;
		    
    my $out = undef;
    for ( my $i = 1; $i <= $done; $i++ ){$out .= "#";}
    for ( my $i = 1; $i <= $remaining; $i++ ){$out .= ".";}
    $out .= " $progress%";
    return $out;
};
