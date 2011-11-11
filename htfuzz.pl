#!/usr/bin/perl

use warnings;
use strict;
use lib './lib';
use lbmap::Signature;
use IO::Socket::INET;

local $SIG{ALRM} = sub { die "TIMEOUT\n"; };
our @reqs;
require 'req.pl';
my $sock;
my $sig = lbmap::Signature->new();

my $server = $ARGV[0];
print "[*] SERVER> $server - ";
my $runs = "Unknown";
$sock = IO::Socket::INET->new(PeerAddr => $server, Timeout => 30) or warn "Unable to connect to $server\n";
if ($sock) {
	alarm 60;
	eval {
		my $r = '';
		print $sock "GET / HTTP/1.1\r\nHost: $server\r\nConnection: Close\r\n\r\n";
		while (<$sock>) {
			if ($_ =~ /^Server: (.*)/) {  $runs = $1; }
			if ($_ =~ /^Via: (.)/) { print "$_"; }
			if ($_ =~ /^proxy/i) { print "$_"; }
			$r .= $_;
		}
		$sig->add_response($r);
	};
	alarm 0;
	if ($@) {
		die unless ( $@ eq "TIMEOUT\n" );
	}
}
print "$runs\n";
for (my $x = 0; $x <  scalar(@reqs); $x++) {
	$sock = IO::Socket::INET->new($server) or warn "Unable to connect to $server\n";
	if ($sock) {
		alarm 20;
		eval {
			my $r = '';
			print $sock "$reqs[$x]\r\nConnection: Close\r\n\r\n";
			print "[-] $reqs[$x]:" if $ENV{'debug'}; #need to s/\n/\\r/ etc..
			while (<$sock>) {
				$r.= $_;
				if ($_ =~ /HTTP\/\d\.\d \d\d\d /) { 
					chomp($_);
					print "$_" if $ENV{'debug'}; 
				}
			}
			$sig->add_response($r);
		};
		alarm 0;
		if ($@) {
			die unless ( $@ eq "TIMEOUT\n" );
		} 
		#print "\n";
		close($sock) or warn "Unable to close socket: $!\n";
	} else {
		print "N/A\n";
	}
}
print $sig->signature();
