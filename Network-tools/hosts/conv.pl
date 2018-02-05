#!/usr/bin/perl
#use strict;
#use warnings;
#use 5.010;
use Term::ANSIColor

my @traceroute;
print "Paste the traceroute here:\n\n";

while ( ($_ = <>) =~ /\S/ ) {
    chomp;
    push @traceroute, $_;
}
print "=============================================================================\n";
my @trac;
my $count = "0";
for my $a (@traceroute){
    if($a =~ m/(^|\ |\(|\[)([1-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})\.([0-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})\.([0-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})\.([0-9]{1}|[1-9]{1}[0-9]{1}|1{1}[0-9]{1}[0-9]{1}|2{1}[0-4]{1}[0-9]{1}|2{1}5{1}[0-5]{1})($|\ |\)|\])/){
    $trac[$count] = "$a";
    $count++;
    }
    else {
    print "$a <-- Line contains no valid IP address!\n";
    }
}
print "\n";
print "Converted output:\n";

for my $i (@trac){
    $i =~ s/\s+/ /g;
#    $i =~ s/^\h+//;
    my @col = split (/ /, $i,);
  
    for my $nmbr (0..$#col){
	if($col[$nmbr] =~ m/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/){
	    my $IPt = "$col[$nmbr]";
		chomp $IPt;
		my $IP = $IPt;
		$IP =~ s/[^\.^\d]//g;
	
	    open my $host, 'hosts-nx';
	    if (grep /$IP /, <$host>) {

		open my $host, 'hosts-nx';
		for $b (<$host>) {
    
		    if ( $b =~ "$IP " ) { 
    			my @col1 = split (/ /, $b,);
    			my $If = "$col1[1]";
    			chomp($If);
    			my $v = $i;
    			$v =~ s/$IP/$If\ \($IP\)/;
    			print "$v\n";
    		    }
    		}
	    }
	    else {
		print "$i"; 
		print color("red"), " <-- no match found\n", color("reset");
	    }
	    last;
	}
    }
}
