package lbmap::lbmap;

use strict;
use warnings;
use IO::Socket::INET;
use IO::Socket::SSL;;

=head1 NAME

lbmap::lbmap - Core functions for lbmap

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';
=head1 SYNOPSIS

    use lbmap::lbmap

    my ($ssl, $host, $port) = lbmap::lbmap->parse_uri('https://www.example.com:8080');

=head1 DESCRIPTION
lbmap::lbmap contains core functions common to all the lbmap utilities.
=cut

sub new {
    my ($class) = @_;
    my $self = {};
    return bless $self, $class;
}

sub parse_uri {
    my $uri = shift;
    my @p = (0, '', 80); #Defaults
    $p[0] = 1 if ($uri =~ m!^https://!);
    $uri =~ m!https?://([^:/]+):?(\d+)?/?!;
    $p[1] = $1;
    if ($2) {
        $p[2]=$2;
    } elsif ($p[0]) {
        $p[2]=443;
    }
    return @p;
}

sub request {
}

1;
