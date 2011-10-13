#!/usr/bin/perl

use warnings;
use strict;
use IO::Socket::INET;
use DBI;

local $SIG{ALRM} = sub { die "TIMEOUT\n"; };
my $dbh = DBI->connect("dbi:SQLite:dbname=data.db","","");

our @reqs;
require 'req.pl';
my $sock;
my $reqs = $dbh->prepare('select * from request');
$reqs->execute();
while (my $request = $reqs->fetchrow_hashref()) {
	my $srv = $dbh->prepare('select * from server');
	$srv->execute();
	while (my $row = $srv->fetchrow_hashref()) {
		print "[*] SERVER> $row->{'hostname'}:$row->{'port'}\n";
		$sock = IO::Socket::INET->new("$row->{'hostname'}:$row->{'port'}") or warn "Unable to connect to $row->{'hostname'}:$row->{'port'}\n";
		if ($sock) {
			alarm 20;
			eval {
				print $sock "$request->{'request'}\r\nConnection: Close\r\n\r\n";
				print "[-] $request->{'request'}:"; #need to s/\n/\\r/ etc..
				my $response = '';
				while (<$sock>) {
					$response .= $_;
				}
				my $resp = $dbh->prepare('insert into response (server_id, request_id, response, time) VALUES(?, ?, ?, ?)');
				$resp->execute($row->{'id'}, $request->{'id'}, $response, join(" ",localtime));
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
}
