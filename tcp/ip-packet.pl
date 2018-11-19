#!/usr/bin/perl -w

use Net::RawIP;
use strict;

# Source book: "Linux Firewalls: Attack Detection and Response", i tested a perl script 
# using Net:RawIP library which is very flexible to design our own raw IP packet. 

my $src = $ARGV[0] or &usage();
my $dst = $ARGV[1] or &usage();
my $str = $ARGV[2] or &usage();
 
my $rawpkt = new Net::RawIP({
	ip => {
		saddr => $src,
		daddr => $dst
	},
	tcp => {}
});
$rawpkt->set({ 
 
	ip => {
		saddr => $src,
		daddr=> $dst
	},
	tcp => {
		source => 10001,
		dest => 8080,
		data => $str,
		psh => 1,
		syn => 1,
	}
});
$rawpkt->send();
print '[+] Sent '.length($str). "bytes of data... \n";
exit 0;
 
sub usage(){
	die "usage: $0 <src> <dst> <str>";
}
