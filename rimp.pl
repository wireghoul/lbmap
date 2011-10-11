#!/usr/bin/perl

use DBI;
require './req.pl';

$dbh = DBI->connect("dbi:SQLite:dbname=data.db","","");

foreach $request (@reqs) {
	$stm = $dbh->prepare("insert into request (request) VALUES(?)");
	$stm->execute($request);
}
