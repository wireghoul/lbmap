package lbmap::lbmap;

use strict;
use warnings;
use IO::Socket::INET;
use IO::Socket::SSL;;
use lbmap::Requests;
use lbmap::Signature;

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
    my $lbmap = lbmap::lbmap->new;
    $lbmap->scan('http://somehost/');
    print $lbmap->{'signature'}-to_string;

=head1 DESCRIPTION
lbmap::lbmap contains core functions common to all the lbmap utilities.
=cut

sub new {
    my ($class) = @_;
    my $self = {};
    my %passive;
    $self->{'passive'} = %passive;
    return bless $self, $class;
}

sub scan {
    my ($self, $target) = @_;
    ($self->{'ssl'}, $self->{'host'}, $self->{'port'}) = $self->_parse_uri($target);
    my $requests = lbmap::Requests->new;
    my $signature = lbmap::Signature->new;
    while ($requests->next) {
        my $response = $self->_request($requests->request);
        # print $response;
        $signature->add($response);
    }
    return $signature->signature();;
}

sub add_passive_detect {
    my ($self, $name, $regex, $function) = @_;
    if (exists($self->{'passive'}{$name})) {
        warn "Overriding existing passive detection $name\n";
    }
    my $caller = caller; #Correct way to find who call the routine ?
    $self->{'passive'}{$name}{'regex'} = $regex;
    $self->{'passive'}{$name}{'callback'} = "$caller::$function";
    return 1;
}

sub _parse_uri {
    my ($self, $uri) = @_;
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

sub _request {
    my ($self, $request) = @_;
    my $response = '';
    if ( $self->_connect ) {
        my $socket = $self->{'socket'};
        # print "Sending $request through $socket\n";
        print $socket $request;
        while (<$socket>) {
            $response .= $_;
        }
    }
    return $response;
}

sub _connect {
    my ($self) = shift;
    $self->{'socket'} = 'fail';
    if ($self->{'ssl'}) {
        $self->{'socket'} = IO::Socket::SSL->new("$self->{'host'}:$self->{'port'}");
    } else {
        $self->{'socket'} = IO::Socket::INET->new("$self->{'host'}:$self->{'port'}");
    }
    return 1 if $self->{'socket'};
}

1;
