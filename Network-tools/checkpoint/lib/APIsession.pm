package lib::APIsession;

use LWP::UserAgent;
use LWP::Protocol::https;
use HTTP::Request::Common;
use JSON;
use Data::Dumper;

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT = qw(login_api check_sid show_session logout_api);


sub login_api {

        my ($server, $id, $sidfile) = @_;
        my $jsonlogin = JSON->new->utf8;
        my $ualogin = LWP::UserAgent->new;
        my $enter = POST(
                "https://$server/web_api/login",
                Content_Type => 'application/json',
                Content      => $jsonlogin->encode($id),
                Accept       => 'application/json'
        );

        my $access = $ualogin->request($enter);
                if ($access->is_success) {
                        my $accessmessage = $access->decoded_content;
                        my $json_join = JSON->new;
                        my $join_data = $json_join->decode($accessmessage);
                        my $sid = $join_data->{'sid'};                        
                open(my $sfile, '>', "$sidfile");
                print $sfile "sid=$sid";
                close $sfile;
                return $sid;
        }
        else {
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
        die;
        };
};

sub logout_api {
        my ($server, $sid) = @_;
        #print "server - $server, sid - $sid\n";
        my $jsonlogout = JSON->new->utf8;
        my $ualogout = LWP::UserAgent->new;
        my $content = '{}';
        my $enter = POST(
                "https://$server/web_api/logout",
                Content_Type => 'application/json',
                Accept       => 'application/json',
                Content      => $content,
                'X-chkp-sid' => $sid
        );
        my $access = $ualogout->request($enter);
        #print Dumper($access);
        if ($access->is_success) {
                print "Logout success\n";
        }
        else {
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
        die;
        };
};

sub check_sid {
	
        my ($server, $sid) = @_;
        my $empty = {};
        my $h = HTTP::Headers->new->push_header('X-chkp-sid');
        my $uasession = LWP::UserAgent->new;
        my $jsonobj = JSON->new->utf8;
        my $enter = POST(
                "https://$server/web_api/keepalive",
                Content_Type => 'application/json',
                Content      => $jsonobj->encode($empty),
                Accept       => 'application/json',
                'X-chkp-sid' => $sid
        );

        my $access = $uasession->request($enter);
                if ($access->is_success) {
                    return $sid;
        }
        else {
                undef $sid;
                return $sid;
        };
};

sub show_session {

        my ($sid, $server) = @_;
        my $objdata = {};
        my $h = HTTP::Headers->new->push_header('X-chkp-sid');
        my $uasession = LWP::UserAgent->new;
        my $jsonobj = JSON->new->utf8;
        my $enter = POST(
                "https://$server/web_api/show-session",
                Content_Type => 'application/json',
                Content      => $jsonobj->encode($objdata),
                Accept       => 'application/json',
                'X-chkp-sid' => $sid
        );

        my $access = $uasession->request($enter);
        if ($access->is_success) {
            my $outputmsg = $access->decoded_content;
            my $json_join = JSON->new;
            my $join_data = $json_join->decode($outputmsg);
            my $changes = $join_data->{'changes'};
			return $changes;
        }
        else {
                print "HTTP POST error code: ", $access->code, "\n";
                print "HTTP POST error message: ", $access->message, "\n";
                die;
        };
};
