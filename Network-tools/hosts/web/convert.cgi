#!/usr/bin/perl
#use strict;
#use warnings;
use 5.010;
#use Term::ANSIColor

    local ($buffer, @pairs, $pair, $name, $value, @traceroute, %FORM);
    # Read in text
    $ENV{'REQUEST_METHOD'} =~ tr/a-z/A-Z/;
    if ($ENV{'REQUEST_METHOD'} eq "POST")
    {
        read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
    }else {
	$buffer = $ENV{'QUERY_STRING'};
    }

print "Content-type:text/html\r\n\r\n";
print "<html>";
print "<head>";
print "<title>host reverse lookup</title>";
print "</head>";
print "<body style=line-height\:1.8>";

    # Split information into name/value pairs
    @pairs = split(/&/, $buffer);
    foreach $pair (@pairs)
    {
	($name, $value) = split(/=/, $pair);
	$value =~ tr/+/ /;
	$value =~ s/%2C/,/g;
	$value =~ s/%3A/:/g;
	$value =~ s/%5B/[/g;
	$value =~ s/%5D/]/g;
	$value =~ s/%28/(/g;
	$value =~ s/%29/)/g;
    }

@traceroute = split ('%0D%0A', $value, );

print "<span style=font-family\:arial><b><font size=3>Original input:<br></font></b></span>";

for my $line (@traceroute){
    print "<span style=font-family\:sans-serif><font size=1>$line<font><br></span>";
    }

my @trac;
my @invalid;
my $count = "0";
for my $a (@traceroute){
    if($a =~ m/(^|\ |\(|\[)([1-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})\.([0-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})\.([0-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})\.([0-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})($|\ |\)|\])/){
    $trac[$count] = "$a";
    $count++;
    }
    else {
    push @invalid, $a;
    chomp;
    }
}
print "<p style=font-family\:arial><b><font size=5> Converted output:</font></b></p>";

for my $i (@trac){
    $i =~ s/\h+/ /g;
    $i =~ s/^\h+//g;
    my @col = split (/ /, $i,);
  
    for my $nmbr (0..$#col){
	if($col[$nmbr] =~ m/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/){
	    my $IPt = "$col[$nmbr]";
		chomp $IPt;
		my $IP = $IPt;
		$IP =~ s/[^\.^\d]//g;
	
	    open my $host, 'hosts-nx';
	    if (grep /$IP/, <$host>) {

		open my $host, 'hosts-nx';
		for $b (<$host>) {
    
		    if ( $b =~ "$IP " ) { 
    			my @col1 = split (/ /, $b,);
    			my $If = "$col1[1]";
    			chomp($If);
    			my $v = $i;
    			$v =~ s/$IPt/$If\ \($IP\)/;
    			print "<span style=font-family\:helvetica><font size=2> $v<br></font></span>";
    		    }
    		}
	    }
	    else {
		print "<span style=font-family\:helvetica><font size=2><i> $i </i></font></span> &nbsp &nbsp &nbsp <span style=color\:red><font size=1><b> &#8678 no match found</b></font><br></span>";
	    }
	    last;
	}
    }
}

if ($#invalid >= 0){
    print "<p style=font-family\:arial><font size=4><b><br>Lines with no valid IP addresses:</b></font></h4></p>";
    for my $line2 (@invalid){
	print "<span style=font-family\:sans-serif><font size=1> $line2 <br></font></span>";
    }
}

print "</body>";
print "</html>";

1;
