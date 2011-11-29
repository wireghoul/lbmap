#!/usr/bin/perl

use warnings;
use strict;
use IO::Socket::INET;
use DBI;

local $SIG{ALRM} = sub { die "TIMEOUT\n"; };
my $dbh = DBI->connect("dbi:SQLite:dbname=data.db","","");

my $sock;
my $reqs = $dbh->prepare('select * from request where active = 1');
$reqs->execute();
while (my $request = $reqs->fetchrow_hashref()) {
	print "\n[*] $request->{'request'}\n"; #need to s/\n/\\r/ etc.
	my $srv = $dbh->prepare('select * from server where active = 1');
	$srv->execute();
	while (my $row = $srv->fetchrow_hashref()) {
		print "[-] $row->{'hostname'}:$row->{'port'} : ";
		$sock = IO::Socket::INET->new("$row->{'hostname'}:$row->{'port'}") or warn "Unable to connect to $row->{'hostname'}:$row->{'port'}\n";
		if ($sock) {
			alarm 20;
			eval {
				print $sock "$request->{'request'}\r\nConnection: Close\r\n\r\n";
				my $response = '';
				my $httpv = '';
				my $code = '';
				while (<$sock>) {
					$response .= $_;
				}
				if ($response =~ m/(HTTP\S+) (\d\d\d) .*/s) { $httpv = $1; $code = $2; }
				print "$httpv $code";
				my $resp = $dbh->prepare('insert into response (server_id, request_id, response, time, http_version, code) VALUES(?, ?, ?, ? , ?, ?)');
				$resp->execute($row->{'id'}, $request->{'id'}, $response, join(" ",localtime), $httpv, $code);
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
