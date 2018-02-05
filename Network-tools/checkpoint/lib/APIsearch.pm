package lib::APIsearch;

use LWP::UserAgent;
use LWP::Protocol::https;
use HTTP::Request::Common;
use JSON;
use Data::Dumper;

use strict;
#use warnings;

use Exporter qw(import);

our @EXPORT = qw(search_object show_rule get_service get_group run_CLI_scr get_objname locate_object show_packages show_task get_networks get_groups get_sgroups get_sranges show_gateway check_flow get_gw search_obj_by_ip);

sub get_gw {
    my ($package, $server, $sid, $debug) = @_;

    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objdata = { "name" => "$package" };
    my $cmd = "show-package";

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
        my $targets = $join_data->{'installation-targets'};
        my $gateways;
        foreach(@$targets){
            push @$gateways, $_->{'name'};
        }
        return $gateways;
    }else{
        my $msg = $join_data->{'message'};
        if ( $msg ){print "$msg\n";exit;}
        else{
            print "HTTP POST error code: ", $access->code, "\n";
            print "HTTP POST error message: ", $access->message, "\n";
            die;
        }
    }

};

sub list_rule {
    my ($rule, $objdict) = @_;

    my $number = $_->{'rule-number'};
    my $src = $_->{'source'};
    my $dst = $_->{'destination'};
    my $svc = $_->{'service'};
    my $action = $_->{'action'};
    my $comm = $_->{'comments'};
    my $vpn = $_->{'vpn'};    
    my $out;

    print $number, ". source (";
    foreach (@$src){
        $out .= "$objdict->{$_}, ";
    }
    $out =~ s/,\ $/)/g;
    print $out;
    undef $out;
        		
    print "  -> dest (";
    foreach (@$dst){
        $out .= "$objdict->{$_}, ";
    }
    $out =~ s/,\ $/)/g;
    print $out;
    undef $out;
        		
    print "  : service (";
    foreach (@$svc){
        $out .= "$objdict->{$_}, ";
    }
    $out =~ s/,\ $/)/g;
    print $out;
    undef $out;
        
    foreach (@$vpn){
        $out .= "$objdict->{$_}, ";        
    }
    $out =~ s/,\ $//g;
    unless ( "$out" eq "Any" ){
	print ", action - $objdict->{$action} (vpn: $out), comments - $comm\n";
	#print "  : vpn ($out)";
	undef $out;
	return;
    }

    print ", action - $objdict->{$action}, comments - $comm\n";

    return;
};

sub match_rule {
    my ($rule, $objdict, $src_list, $dst_list, $svc_list) = @_;

    my $number = $_->{'rule-number'};
    my $src = $_->{'source'};
    my $dst = $_->{'destination'};
    my $svc = $_->{'service'};
    my $action = $_->{'action'};
    my $comm = $_->{'comments'};
    my $vpn = $_->{'vpn'};
    my $status = $_->{'enabled'};
    my $out;
    my $match;

    return if "$status" ne "true" and "$status" ne "1";

    $out .= "$number. source (";
    foreach (@$src){
        $out .= "$objdict->{$_}, ";
        my $obj = "$objdict->{$_}";
        if ( lc "$obj" eq "any" ){$match = "true";last;}
        foreach (@$src_list){
    	    if ( "$obj" eq "$_" ){$match = "true";last;}
        }
    }
    $out =~ s/,\ $/)/g;
    
    if ( "$match" eq "true" ){
	$out .= "  -> dest (";
	undef $match;
	foreach (@$dst){
    	    $out .= "$objdict->{$_}, ";
    	    my $obj = "$objdict->{$_}";
    	    if ( lc "$obj" eq "any" ){$match = "true";last;}
    	    foreach (@$dst_list){
    		if ( "$obj" eq "$_" ){$match = "true";last;}
    	    }
	}
	$out =~ s/,\ $/)/g;
    }
    
    if ( "$match" eq "true" ){
	undef $match;
	$out .= "  : service (";
	foreach (@$svc){
    	    $out .= "$objdict->{$_}, ";
    	    my $obj = "$objdict->{$_}";
    	    if ( lc "$obj" eq "any" ){$match = "true";last;}
    	    foreach (@$svc_list){
    		if ( "$obj" eq "$_" ){$match = "true";last;}
    	    }
	}
	$out =~ s/,\ $/)/g;
    }
    
    if ( "$match" eq "true" ){
	my $out_vpn;
	foreach (@$vpn){
	    $out_vpn .= "$objdict->{$_}, ";
	}
	$out_vpn =~ s/,\ $//g;
	if ( "$out_vpn" ne "Any" ){
	    $out .= ", action - $objdict->{$action} (vpn: $out_vpn), comments - $comm\n";
	}else{
	    $out .= ", action - $objdict->{$action}, comments - $comm\n";
	}
	my $act = $objdict->{$action};
	$act =~ s/Drop/denied/;
	$act =~ s/Accept/allowed/;
	print "\nTraffic is ", $act, "\nMatching rule:\n ", $out, "\n";
	exit;
    }
    return;
};

sub check_flow {
    my ($sid, $server, $package, $src_list, $dst_list, $svc_list, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $name = "$package Network";
    
    my $offset = 0;
    my $total = 0;
    my $limit = 500;
    
    while ( $offset == 0 || $offset < $total ){
    
	my $objdata = { "name" => "$name", "limit" => "$limit", "offset" => "$offset", "details-level" => "standard" };
	my $cmd = "show-access-rulebase";
    
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
    	    my $msg = $join_data->{'message'};
	
	    if ( $msg =~ /^.*not\ found/ ){
		$name = "$package Security";
		$objdata = { "name" => "$name", "limit" => "$limit", "offset" => "$offset", "details-level" => "standard" };
		$enter = POST(
        		"https://$server/web_api/$cmd",
        		Content_Type => 'application/json',
        		Content      => $jsonobj->encode($objdata),
        		Accept       => 'application/json',
        		'X-chkp-sid' => $sid
		);
	    
		$access = $uasession->request($enter);
		$outputmsg = $access->decoded_content;
    		$json_join = JSON->new->utf8;
    		$join_data = $json_join->decode($outputmsg);
	    }
	
    	    if ($access->is_success) {
        	if ( $debug ){print $outputmsg, "\n";}
        	my $rulebase = $join_data->{'rulebase'};
        	my $objdict = $join_data->{'objects-dictionary'};
        	my $objdict_hash;
        	$total = $join_data->{'total'};
        	foreach (@$objdict){
        	    $objdict_hash->{$_->{uid}} = "$_->{'name'}";
        	}

        	foreach (@$rulebase){
        	    my $type = $_->{'type'};
        	    if ( "$type" eq "access-rule" ){
        		list_rule($_, $objdict_hash) unless $src_list;
        		match_rule($_, $objdict_hash, $src_list, $dst_list, $svc_list) if $src_list;
        	    }
        	    else{
        		print "\n", $_->{'name'}, ":\n" unless $src_list;
        		my $rules = $_->{'rulebase'};
        		foreach (@$rules){
        		    list_rule($_, $objdict_hash) unless $src_list;    
        		    match_rule($_, $objdict_hash, $src_list, $dst_list, $svc_list) if $src_list;
        		}
        	    }
        	}
        	$offset += $limit;
	    }else{
    		my $msg = $join_data->{'message'};
        	if ( $msg ){print "$msg\n";exit;}
        	else{
            	    print "HTTP POST error code: ", $access->code, "\n";
            	    print "HTTP POST error message: ", $access->message, "\n";
            	    die;
        	}
    	    }
        }    	    
};

sub show_gateway {
    my ($sid, $server, $string, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objdata = { "details-level" => "full", "limit" => "100" };
    my $enter = POST(
            "https://$server/web_api/show-gateways-and-servers",
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
            my $objects = $join_data->{'objects'};
            my $interfaces;
            if ( scalar (grep { $_ } @$objects) > 0 ){
        	foreach (@$objects){
        	    my $match;
        	    my $gateway = $_->{'name'};
        	    my $cluster = $_->{'cluster-member-names'};
        	    foreach (@$cluster){
        		if ( "$_" eq "$string" ){$match = "true";}
        	    }
        	    if ( "$gateway" eq "$string" ){$match = "true";}
        	    if ( "$match" eq "true" ){
        		my $type = $_->{'type'};
        		my $policy = $_->{'policy'};
        		my $policy_name = $policy->{'access-policy-name'};
        		my $ifaces = $_->{'interfaces'};
        		foreach (@$ifaces){
        		    push @$interfaces, { ifname => "$_->{'interface-name'}", ip => "$_->{'ipv4-address'}", mask => "$_->{'ipv4-mask-length'}" };
        		}
        		return ($policy_name, $type, $interfaces);
        	    }
        	    foreach (@$cluster){
        		
        	    }
        	}		    		
    	    }
	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    	    
};

sub show_task {
    my ($sid, $server, $task_id, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objdata = { "details-level" => "full", "task-id" => "$task_id" };
    
    my $enter = POST(
            "https://$server/web_api/show-task",
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
            my $tasks = $join_data->{'tasks'};
            if ( scalar (grep { $_ } @$tasks) > 0 ){
        	my $task_name = @$tasks[0]->{'task-name'};
    		my $status = @$tasks[0]->{'status'};
    		my $progress = @$tasks[0]->{'progress-percentage'};
    		my $details = @$tasks[0]->{'task-details'};
    		my $msg_arr;
    		foreach (@$details){
    		    my $detail = $_;
    		    foreach (keys %$detail){
    			if ( "$_" eq "stagesInfo" ){
    			    my $stInfo = $detail->{$_};
    				foreach (@$stInfo){
    				    my $stage = $_;
    				    foreach (keys %$stage){
    					if ( "$_" eq "messages" ){
    					    my $messages = $stage->{$_};
    					    foreach (@$messages){
    						my $elem = $_;
    						my $msgtype;
    						my $message;
    						foreach (keys %$elem){
    						    if ( "$_" eq "type" ){
    							$msgtype = $elem->{$_};
    						    }
    						    if ( "$_" eq "message" ){
    							$message = $elem->{$_};
    						    }
    						}
    						push @$msg_arr, { "$msgtype" => "$message" };
    					    }
    					}
    				    }
    				}
    			}
    		    }
    		}
    		return ($task_name, $status, $progress, $msg_arr);
    	    }
	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    	    
};

sub get_sgroups {
    my ($sid, $server, $limit, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $sgroups;
    my $offset = 0;
    my $total = 0;
    $limit = "500" unless ( $limit );
    
    while ( $offset == 0 || $offset < $total ){
    my $objdata = { "details-level" => "full", "offset" => "$offset", "limit" => "$limit" };
    
    my $enter = POST(
            "https://$server/web_api/show-service-groups",
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
            my $sgrp = $join_data->{'objects'};
            $total = $join_data->{'total'};
            foreach (@$sgrp){
        	my $name = $_->{'name'};
		my $members = $_->{'members'};
		foreach (@$members){
        	    push @$sgroups, { name => "$name", member => "$_->{'name'}" };
        	}
    	    }
		$offset = $offset + 500;
	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    }
    return ($total, $sgroups);
    	    
};

sub get_sranges {
    my ($sid, $server, $type, $limit, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $sranges;
    my $offset = 0;
    my $total = 0;
    my $count = 0;
    $limit = "500" unless ( $limit );

    while ( $offset == 0 || $offset < $total ){
    my $objdata = { "details-level" => "standard", "type" => "$type", "offset" => "$offset", "limit" => "$limit" };

    my $enter = POST(
            "https://$server/web_api/show-objects",
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
            my $srng = $join_data->{'objects'};
            $total = $join_data->{'total'};
            foreach (@$srng){
                if ( $_->{'port'} =~ /^\d+-\d+$/ ){
                    push @$sranges, { port => "$_->{'port'}", type => "$_->{'type'}", name => "$_->{'name'}" };
		    $count += 1;
		}
            }
                $offset = $offset + 500;
        }else{
            my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    }
    return ($count, $sranges);

};

sub get_groups {
    my ($sid, $server, $limit, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $groups;
    my $offset = 0;
    my $total = 0;
    $limit = "20" unless ( $limit );
    
    while ( $offset == 0 || $offset < $total ){
    my $objdata = { "details-level" => "full", "offset" => "$offset", "limit" => "$limit" };
        
    my $enter = POST(
            "https://$server/web_api/show-groups",
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
            my $grp = $join_data->{'objects'};
            $total = $join_data->{'total'};
            foreach (@$grp){
        	my $name = $_->{'name'};
		my $members = $_->{'members'};
		foreach (@$members){
#		    print $name, "|", $_->{'name'}, "\n";
        	    push @$groups, { name => "$name", member => "$_->{'name'}" };
        	}
    	    }
		$offset += $limit;
	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    }
    return ($total, $groups);
    	    
};

sub get_networks {
    my ($sid, $server, $limit, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $networks;
    my $offset = 0;
    my $total = 0;
    $limit = "500" unless ( $limit );
    
    while ( $offset == 0 || $offset < $total ){
    my $objdata = { "details-level" => "full", "offset" => "$offset", "limit" => "$limit" };
    
    my $enter = POST(
            "https://$server/web_api/show-networks",
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
            my $nets = $join_data->{'objects'};
            $total = $join_data->{'total'};
            foreach (@$nets){
        	my $name = $_->{'name'};
    		my $subnet = $_->{'subnet4'};
    		my $mask = $_->{'mask-length4'};
    		my $network = "$subnet/$mask";
    		push @$networks, { name => "$name", network => "$network" };
    	    }
		$offset = $offset + 500;
	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    }
    return ($total, $networks);
    	    
};

sub show_packages {
    my ($sid, $server, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objdata = { "limit" => "500", "offset" => "0", "details-level" => "standard" };
    
    my $enter = POST(
            "https://$server/web_api/show-packages",
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
    	    my $packages = $join_data->{'packages'};
    	    print "Policy packages:\n";
    	    foreach (@$packages){
        	my $pkgname = $_->{'name'};
        	print " $pkgname\n";
    	    }
    	    print "\n";
    	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    	    
};

sub search_obj_by_ip {
    my ($sid, $server, $string, $debug, $limit, $nonets) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    if ( not $limit ){$limit = 500;}
    my $ip_filter = "false";
    
#Commented out as it does not work correctly on .16 mgmt server    
    $ip_filter = "true" if $string =~ /^(\d{1,3}\.){1,3}(\d{1,3})?\*?$/;
    my $objdata = { "limit" => "$limit", "offset" => "0", "details-level" => "standard", "filter" => "$string" , "ip-only" => "$ip_filter" };
    
    my $enter = POST(
            "https://$server/web_api/show-objects",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );
    
    my $access = $uasession->request($enter);
	my $outputmsg = $access->decoded_content;
    	my $json_join = JSON->new->utf8;
        my $join_data = $json_join->decode($outputmsg);
        if ($access->is_success){
            if ( $debug ){print $outputmsg, "\n";}
    	    my $objects = $join_data->{'objects'};
	    my $obj_list;
	    my $out_list;
    	    foreach (@$objects){
        	my $objname = $_->{'name'};
        	my $type = $_->{'type'};
        	my $comments = $_->{'comments'};
        	my $out;
        	if ( $type eq "network" ){
        	    my $subnet = $_->{'subnet4'};
        	    my $ml = $_->{'mask-length4'};
        	    $out .= "2$type: $objname ($subnet/$ml)";
        	    $objname =~ s/^/2/;
        	}
        	elsif ( $type eq "host" ){
        	    my $ipv4 = $_->{'ipv4-address'};
        	    $out .= "1$type: $objname ($ipv4)";
        	    $objname =~ s/^/1/;
        	}
        	else{
        	    $out .= "3$type: $objname";
        	    $objname =~ s/^/3/;
        	}
        	if ( $comments ){$out .= ", comments: $comments";}
        	if ( $type eq "host" or $type eq "network" or $type eq "group" ){
        	    if ( $nonets ){
        		push @$obj_list, $objname unless $type eq "network";
        	    }else{
        		push @$obj_list, $objname;
        	    }
        	    push @$out_list, $out;
        	}
    	    }
    	    return unless $out_list;
    	    my $sort_out_list;
    	    @$sort_out_list = sort @$out_list;
    	    foreach(@$sort_out_list){
    		$_ =~ s/^\d//;
    	    }
    	    my $sort_obj_list;
    	    @$sort_obj_list = sort @$obj_list;
    	    foreach(@$sort_obj_list){
    		$_ =~ s/^\d//;
    	    }
    	    return ($sort_out_list, $sort_obj_list);    	    
    	}else{
    	    my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
    	    
};

sub search_object {
    my ($sid, $server, $string1, $string2, $verbose, $debug, $limit, $network, $objtype) = @_;
    my $string;
    my $objdata;
    my $ip;
    my $net;
    my $mask;
    my $subnet;
    if ( $string1 ){$string = $string1};
    if ( $string2 ){$string = $string2};
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $wildcard;
    my $match_in;
    my $ip_filter = "false";
    my $det_lvl = "standard";
    
    my $string_mod = $string;
    my @words = split (/\s+/, $string);
    my $wc = scalar (@words);
    if ( $wc > "1" ){$string_mod =~ s/\s+/*/g}

    if ( $network ){
        $net = "$string";
        $mask = "$string";
        $net =~ s/\/.*$//;
        $mask =~ s/^.*\///;
        $string_mod = $net;
    }

#Commented out as it does not work correctly on .16 mgmt server    
    $ip_filter = "true" if $string =~ /^(\d{1,3}\.){1,3}(\d{1,3})?\*?$/;
    $det_lvl = "full" if $verbose;
    
    if ( ! $limit ){$limit = "500";}    
    if ( $objtype  ){$objdata = { "limit" => "$limit", "offset" => "0", "details-level" => "$det_lvl", "type" => "$objtype", "order" => [ { "ASC" => "name" } ], "filter" => "$string_mod", "ip-only" => "$ip_filter" };}
    else{$objdata = { "limit" => "$limit", "offset" => "0", "details-level" => "$det_lvl", "order" => [ { "ASC" => "name" } ], "filter" => "$string_mod", "ip-only" => "$ip_filter" };}

    my $enter = POST(
            "https://$server/web_api/show-objects",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );

    my $access = $uasession->request($enter);
        if ($access->is_success) {
            my $outputmsg = $access->decoded_content;
            if ( $debug ){print $outputmsg, "\n";}
            my $json_join = JSON->new->utf8;
            my $join_data = $json_join->decode($outputmsg);
            my $total = $join_data->{'total'};
            my $count = "0";

            if ( $total != "0" ){
                if ( $string =~ /^.{3,}\*$/){$wildcard = 1;}
                my $objects = $join_data->{'objects'};
                foreach (@$objects){
                    my $type = $_->{'type'};
                    my $ipaddr = $_->{'ipv4-address'};
                    my $comments = $_->{'comments'};
                    chomp($comments);
                    my $name = $_->{'name'};
                    my $subnet4 = $_->{'subnet4'};
                    my $ml4 = $_->{'mask-length4'};

                    if ( $subnet4 ){$subnet = "$subnet4/$ml4";}

                    if ( $verbose ){
                        if ( $comments && $comments =~ /$string/i ){$match_in = "comments";}
                    }
                    if ( $wildcard == 1 ){
                        if ( $name && $name =~ /^$string/i ){$match_in = "object name";}
                        if ( $ipaddr && $ipaddr =~ /^$string/ ){$match_in = "IP address";}
                        if ( $subnet4 && $subnet4 =~ /^$string/ ){$match_in = "subnet";}
                    }else{
                        if ( $name && lc "$string" eq lc "$name" ){$match_in = "object name";}
                        if ( $ipaddr && "$string" eq "$ipaddr" ){$match_in = "IP address";}
                        if ( $subnet4 && "$net" eq "$subnet4" && "$mask" eq "$ml4" ){$match_in = "subnet";}
                    }

                    if ( $match_in ){
                        $count++;
                        if ( $ipaddr ){
                            $ip = "$ipaddr";
                            $ip =~ s/^/(/;
                            $ip =~ s/$/)/;
                        }
                        if ( $subnet ){
                            $ip = "$subnet";
                            $ip =~ s/^/(/;
                            $ip =~ s/$/)/;
                        }
                        if ( $comments ){
                            my $out = "$type: $name $ip | Matched in field: $match_in | Comments: $comments";
                            $out =~ s/\ +/ /g;
                            print $out, "\n";
                        }else{
                    	    my $out = "$type: $name $ip | Matched in field: $match_in";
                            $out =~ s/\ +/ /g;
                            print $out, "\n";                            
                        }
                    }
                        undef $match_in; 
                        undef $ip; 
                        undef $ipaddr;
                        undef $subnet;                                                
                }
                undef $wildcard;
#                if ( $count == "0" ){print "\nNo $objtype type of objects matching search string were found\n";}
            }
            #else{
            #    print "\nNo $objtype type of objects matching search string were found\n";
            #}
        }else{
            print "HTTP POST error code: ", $access->code, "\n";
            print "HTTP POST error message: ", $access->message, "\n";
            die;
        }

};

sub show_rule {
    my ($sid, $server, $string, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;

    my $layer = $string;
    $layer =~ s/_.*$//;
#    $layer =~ s/$/ Network/;
    my $uid = $string;
    $uid =~ s/^.*_//;

    my $objdata = { "layer" => "$layer", "uid" => "$uid", "details-level" => "full" };

    my $enter = POST(
            "https://$server/web_api/show-access-rule",
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
            my $ruid = $join_data->{'uid'};
            if ( $ruid ){
                print "Layer: $layer\nRule uid: $uid\n\n";

                my $sources = $join_data->{'source'};
                print " Source(s):\n";
                foreach (@$sources){
                    my $name = $_->{'name'};
                    my $type = $_->{'type'};
                    my $ip = $_->{'ipv4-address'};
                    if ( $ip ){
                        $ip =~ s/^/ (/;
                        $ip =~ s/$/)/;
                    }
                    print "  $type: $name$ip\n";
                }

                my $dnations = $join_data->{'destination'};
                print "\n Destination(s):\n";
                foreach (@$dnations){
                    my $name = $_->{'name'};
                    my $type = $_->{'type'};
                    my $ip = $_->{'ipv4-address'};
                    if ( $ip ){
                        $ip =~ s/^/ (/;
                        $ip =~ s/$/)/;
                    }
                    print "  $type: $name$ip\n";
                }

                my $services = $join_data->{'service'};
                print "\n Service(s):\n";
                foreach (@$services){
                    my $name = $_->{'name'};
                    my $type = $_->{'type'};
                    $type =~ s/^service-//;
                    my $port = $_->{'port'};
                    if ( $port ){
                        $port =~ s/^/ ($type:/;
                        $port =~ s/$/)/;
                    }
                    print "  $name$port\n";
                }

                my $action = $join_data->{'action'}->{'name'};
                print "\n Action: $action\n";
                my $track = $join_data->{'track'}->{'name'};
                print " Track: $track\n";
                my $enabled = $join_data->{'enabled'};
                if ( "$enabled" eq "true" ){print " Enabled\n";}
                else{print " Disabled\n";}
                my $comm = $join_data->{'comments'};
                if ( $comm ){print "\n Comments: $comm\n\n";}
            }
        }else{
            my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
};

sub get_service {
    my ($sid, $server, $string, $proto, $port, $debug) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objdata;
    my $objtype;

    if ( $proto ){
        $objtype = "service-$proto";
        $objdata = { "limit" => "500", "offset" => "0", "type" => "$objtype", "details-level" => "full", "in" => [ "text" => "$port" ] };
    }else{
        $objdata = { "limit" => "500", "offset" => "0", "details-level" => "full", "in" => [ "name" => "$string" ] };
    }

    my $enter = POST(
            "https://$server/web_api/show-objects",
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

            my $total = $join_data->{'total'};
            if ( $total != "0" ){
                my $objects = $join_data->{'objects'};
                my $services;
                foreach (@$objects){
                    my $match;
                    my $name = $_->{'name'};
                    my $stout = $_->{'session-timeout'};
                    my $pnumber = $_->{'port'};
                    my $svctype = $_->{'type'};
                    if ( $proto ){
                        if ( $pnumber && "$pnumber" eq "$port" ){$match = "true";}
                    }else{
                        if ( $name && lc "$name" eq lc "$string" && $svctype ){
                            if ( $svctype =~ /^service-(tcp|udp|sctp|other)$/ ){$match = "true";}
                        }
                    }
                    if ( $match ){
                	push @$services, { name => "$name", type => "$svctype", pnumber => "$pnumber", st => "$stout" };
            	    }
                }
                return $services;
            }

        }else{
            my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";exit;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
};

sub get_group {
    my ($sid, $server, $string, $debug, $svc) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $objname;
    my $objtype;
    my $objdata = { "name" => "$string", "details-level" => "full" };
    my $cmd = "show-group";
    if ( $svc ){$cmd = "show-service-group";}
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
            my $objname = $join_data->{'name'};
            my $objtype = $join_data->{'type'};
            my $members = $join_data->{'members'};

            if ( $objname ){
        	my $memb;
                my $objc = scalar(grep { $_ } @$members );
                if ( $objc > "0" ){
                    foreach (@$members){
                        my $name = $_->{'name'};
                        my $type = $_->{'type'};
                        my $ip = $_->{'ipv4-address'};
                        if ( $ip ){
                            $ip =~ s/^/(/;
                            $ip =~ s/$/)/;
                        }
                        push @$memb, { name => "$name", type => "$type", ip => "$ip" };
                    }
                }
        	return ($objname, $objtype, $memb);
            }
        }else{
            my $msg = $join_data->{'message'};
            if ( $msg ){print "$msg\n";return;}
            else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }
        }
};

sub run_CLI_scr {
    my ($sid, $server, $target, $scr) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $taskid;
#    my $objname;
    my $respMsg;
#    my $objdata = { "script-name" => "Get object name from IP", "script" => "/home/admin/scripts/query_ip.sh $string", "targets" => "hollywood-sm01" };
    my $objdata = { "script-name" => "Remote script", "script" => "$scr", "targets" => "$target" };
    my $enter = POST(
                "https://$server/web_api/run-script",
                Content_Type => 'application/json',
                Content      => $jsonobj->encode($objdata),
                Accept       => 'application/json',
                'X-chkp-sid' => $sid
        );

        my $access = $uasession->request($enter);
                if ($access->is_success) {
                    my $outputmsg = $access->decoded_content;
                    my $json_join = JSON->new->utf8;
                    my $join_data = $json_join->decode($outputmsg);
                    my @tasks = @{ $join_data->{'tasks'} };
                    $taskid =  @tasks[0]->{'task-id'};
                    chomp($taskid);
                }else{
                    print "HTTP POST error code: ", $access->code, "\n";
                    print "HTTP POST error message: ", $access->message, "\n";
                    die;
                }

    my $objdata = { "details-level" => "full", "task-id" => "$taskid" };
    my $enter = POST(
                "https://$server/web_api/show-task",
                Content_Type => 'application/json',
                Content      => $jsonobj->encode($objdata),
                Accept       => 'application/json',
                'X-chkp-sid' => $sid
        );

        my $statuscode = "in progress";
        while ( "$statuscode" eq "in progress" ){
            my $access = $uasession->request($enter);
            if ($access->is_success) {
                my $outputmsg = $access->decoded_content;
                my $json_join = JSON->new->utf8;
                my $join_data = $json_join->decode($outputmsg);
                my $tasks = $join_data->{'tasks'};
                my $taskdetails = @$tasks[0]->{'task-details'} ;
                $statuscode = @$taskdetails[0]->{'statusCode'};

                if ( "$statuscode" eq "succeeded"  ){
                    #$objname = @$taskdetails[0]->{'statusDescription'};
                    $respMsg = @$taskdetails[0]->{'responseMessage'};
                }
            }else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }

        }
        return $respMsg;

};

sub get_objname {
    my ($sid, $server, $string, $debug, $network) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $type;
    my $subnet;
    my $net;
    my $mask;

    my $string_mod = $string;
    my @words = split (/\s+/, $string);
    my $wc = scalar (@words);
    if ( $wc > "1" ){$string_mod =~ s/\s+/*/g}

    if ( $network ){
        $net = "$string";
        $mask = "$string";
        $net =~ s/\/.*$//;
        $mask =~ s/^.*\///;
        $string_mod = $net;
    }

    my $objdata = { "limit" => "500", "offset" => "0", "details-level" => "standard", "order" => [ { "ASC" => "name" } ], "in" => [ "text" => "$string_mod" ] };
        
    my $enter = POST(
            "https://$server/web_api/show-objects",
            Content_Type => 'application/json',
            Content      => $jsonobj->encode($objdata),
            Accept       => 'application/json',
            'X-chkp-sid' => $sid
    );

    my $access = $uasession->request($enter);
        if ($access->is_success) {
            my $outputmsg = $access->decoded_content;
            if ( $debug ){print $outputmsg, "\n";}
            my $json_join = JSON->new->utf8;
            my $join_data = $json_join->decode($outputmsg);
            my $total = $join_data->{'total'};

            if ( $total != "0" ){
                my $objects = $join_data->{'objects'};
                foreach (@$objects){
                    my $ipaddr = $_->{'ipv4-address'};
                    my $subnet4 =$_->{'subnet4'};
                    my $ml4 = $_->{'mask-length4'};
                    my $name = $_->{'name'};
                    my $match;

                    if ( $subnet4 ){$subnet = "$subnet4/$ml4";}

                    if ( $ipaddr && "$ipaddr" eq "$string" ){$match = "true";}
                    if ( $name && lc "$name" eq lc "$string" ){$match = "true";}
                    if ( $subnet4 && "$subnet4" eq "$net" && "$ml4" eq "$mask" ){$match = "true";}

                    if ( $match ){
                        $type = $_->{'type'};
                        return ($name, $ipaddr, $subnet, $type);
                    }
                }
            }
        }else{
            print "HTTP POST error code: ", $access->code, "\n";
            print "HTTP POST error message: ", $access->message, "\n";
            die;
        }
};

sub locate_object {
    my ($sid, $server, $type, $objects, $verbose, $debug, $brief) = @_;
    my $h = HTTP::Headers->new->push_header('X-chkp-sid');
    my $uasession = LWP::UserAgent->new;
    my $jsonobj = JSON->new->utf8;
    my $rule_usg;
    my $object_usg;
    my $nat_usg;
    
    for my $objname (@$objects){
    my $objdata = { "name" => "$objname", "indirect" => "false" };
    my $enter = POST(
                "https://$server/web_api/where-used",
                Content_Type => 'application/json',
                Content      => $jsonobj->encode($objdata),
                Accept       => 'application/json',
                'X-chkp-sid' => $sid
        );

    my $access = $uasession->request($enter);
#        if ($access->is_success) {
            my $outputmsg = $access->decoded_content;
            if ( $debug ){print $outputmsg, "\n";}
            my $json_join = JSON->new->utf8;
            my $join_data = $json_join->decode($outputmsg);
            my $direct = $join_data->{'used-directly'};
            my $usage = $direct->{'total'};
            
            if ( $usage > 0 ){
                my $objusg = $direct->{'objects'};
                my $accusg = $direct->{'access-control-rules'};
                my $natusg = $direct->{'nat-rules'};
                my $accc = scalar(grep { $_ } @$accusg );
                my $objc = scalar(grep { $_ } @$objusg );
                my $natc = scalar(grep { $_ } @$natusg );

                if ( $accc != "0" ){
                    foreach (@$accusg){
                        my $package = $_->{'package'};
                        my $layer = $_->{'layer'};
                        my $rule = $_->{'rule'};
                        my $position = $_->{'position'};
                        my $pkgname = $package->{'name'};
                        my $layername = $layer->{'name'};
                        my $rulename = $rule->{'uid'};
                        my $rulecol = $_->{'rule-columns'};
                        my $install_on;
                        foreach (@$rulecol){
                    	    if ( "$_" eq "install-on" && scalar(grep $_, @$rulecol) == 1 ){$install_on = "true"}
                    	}
                        unless ( $install_on ){
			    my $out = "  Rule ID: \"$layername\_$rulename\" | Rule nr: $position | $objname as: ";
                    	    foreach (@$rulecol){
				$out .= "$_ ";
                    	    }
                    	if ( $verbose ){$out = rule_verbose($rulename, $layername, $out, undef);}
                    	    push @$rule_usg, $out;
                        }
                    }
                }
                
                if ( $natc != "0" ){
                    foreach (@$natusg){
                        my $package = $_->{'package'};
                        my $rule = $_->{'rule'};
                        my $position = $_->{'position'};
                        my $pkgname = $package->{'name'};
                        my $rulename = $rule->{'uid'};
                        my $rulecol = $_->{'rule-columns'};
                        my $install_on;
                        foreach (@$rulecol){
                    	    if ( "$_" eq "install-on" && scalar(grep $_, @$rulecol) == 1 ){$install_on = "true"}
                    	}
                        unless ( $install_on ){
			    my $out = "  Rule ID: \"$pkgname\_$rulename\" | Rule nr: $position | $objname as: ";
                    	    foreach (@$rulecol){
				$out .= "$_ ";
                    	    }
                    	if ( $verbose ){$out = rule_verbose($rulename, $pkgname, $out, "true");}
                    	    push @$nat_usg, $out;
                        }
                    }
                }

                if ( $objc != "0" ){
                    foreach (@$objusg){
                        my $name = $_->{'name'};
                        my $type = $_->{'type'};
                        my $out = "  $objname in $type: $name";
                        push @$object_usg, { "objname" => "$objname", "type" => "$type", "name" => "$name" };
                    }
                }
#                my $thrusg = $usage->{'threat-prevention-rules'};
            }                        
#        }else{
#            print "HTTP POST error code: ", $access->code, "\n";
#            print "HTTP POST error message: ", $access->message, "\n";
#            die;
#        }
    }
    return ($rule_usg, $object_usg, $nat_usg);

    sub rule_verbose {
        my ($rulename, $layername, $out, $nat) = @_;
        my $h = HTTP::Headers->new->push_header('X-chkp-sid');
        my $uasession = LWP::UserAgent->new;
        my $jsonobj = JSON->new->utf8;
        my $objdata;
        my $cmd;
        unless ( $nat ){
    	    $objdata = { "uid" => "$rulename", "layer" => "$layername" };
    	    $cmd = "show-access-rule";
    	}else{
    	    $objdata = { "uid" => "$rulename", "package" => "$layername" };
    	    $cmd = "show-nat-rule";
    	}
        my $enter = POST(
                "https://$server/web_api/$cmd",
                Content_Type => 'application/json',
                Content      => $jsonobj->encode($objdata),
                Accept       => 'application/json',
                'X-chkp-sid' => $sid
        );

        my $access = $uasession->request($enter);
            if ($access->is_success) {
                my $outputmsg = $access->decoded_content;
                my $json_join = JSON->new->utf8;
                my $join_data = $json_join->decode($outputmsg);
                unless ( $nat ){
            	    my $sources = $join_data->{'source'};
		    $out .= "| Details: \n   src: ";
            	    foreach (@$sources){
                	my $source = $_->{'name'};
			$out .= "$source ";
            	    }
            	    my $dnations = $join_data->{'destination'};
            	    $out .= "| dst: ";
            	    foreach (@$dnations){
                	my $dnation = $_->{'name'};
			$out .= "$dnation ";
            	    }
            	    my $services = $join_data->{'service'};
            	    $out .= "| svc: ";
            	    foreach (@$services){
                	my $service = $_->{'name'};
			$out .= "$service ";
            	    }
            	    my $action = $join_data->{'action'};
		    $out .= "| action: $action->{'name'}";
            	    my $track = $join_data->{'track'};
		    $out .= " | track: $track->{'name'}";
            	    my $enabled = $join_data->{'enabled'};
            	    if ( $enabled ){
			$out .= " | enabled";
            	    }else{
			$out .= " | disabled";
            	    }
                }else{
            	    my $o_src = $join_data->{'original-source'}->{'name'};
            	    my $o_dst = $join_data->{'original-destination'}->{'name'};
            	    my $o_svc = $join_data->{'original-service'}->{'name'};
            	    my $t_src = $join_data->{'translated-source'}->{'name'};
            	    my $t_dst = $join_data->{'translated-destination'}->{'name'};
            	    my $t_svc = $join_data->{'translated-service'}->{'name'};
            	    my $method = $join_data->{'method'};
            	    $out .= "| Details: \n   $method NAT | original ( src: $o_src, dst: $o_dst, svc: $o_svc ) | translated ( src: $t_src, dst: $t_dst, svc: $t_svc )";
            	    my $enabled = $join_data->{'enabled'};
            	    if ( $enabled =~ "true" ){
			$out .= " | enabled";
            	    }else{
			$out .= " | disabled";
            	    }
                }
		return $out;
            }else{
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
            }

    };

};
