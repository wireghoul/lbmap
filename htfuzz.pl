#!/usr/bin/perl

use warnings;
use strict;
use IO::Socket::INET;

local $SIG{ALRM} = sub { die "TIMEOUT\n"; };
our @reqs;
require 'req.pl';
my $sock;

my $server = $ARGV[0];
print "[*] SERVER> $server\n";
my $runs = "Unknown";
$sock = IO::Socket::INET->new(PeerAddr => $server, Timeout => 30) or warn "Unable to connect to $server\n";
if ($sock) {
	alarm 60;
	eval {
		print $sock "GET / HTTP/1.1\r\nHost: $server\r\nConnection: Close\r\n\r\n";
		while (<$sock>) {
			if ($_ =~ /^Server: (.*)/) {  $runs = $1; }
			if ($_ =~ /^Via: (.)/) { print "[-] $_"; }
			if ($_ =~ /^proxy/i) { print "[-] $_"; }
		}
	};
	alarm 0;
	if ($@) {
		die unless ( $@ eq "TIMEOUT\n" );
	}
}
print "[*] Server: $runs\n";
foreach my $request (@reqs) {
	$sock = IO::Socket::INET->new($server) or warn "Unable to connect to $server\n";
	if ($sock) {
		alarm 20;
		eval {
			print $sock "$request\r\nConnection: Close\r\n\r\n";
			print "[-] $request:"; #need to s/\n/\\r/ etc..
			while (<$sock>) {
				if ($_ =~ /HTTP\/\d\.\d \d\d\d /) { 
					chomp($_);
					print "$_"; 
				}
			}
		};
		alarm 0;
		if ($@) {
			die unless ( $@ eq "TIMEOUT\n" );
		} 
		print "\n";
		close($sock) or warn "Unable to close socket: $!\n";
	} else {
		print "N/A\n";
	}
}
