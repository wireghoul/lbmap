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
# local $SIG{ALRM} = sub { die "TIMEOUT\n"; };

=head1 SYNOPSIS

    use lbmap::lbmap
    my $lbmap = lbmap::lbmap->new;
    $lbmap->scan('http://somehost/');
    print $lbmap->{'signature'}-to_string;

=head1 DESCRIPTION
lbmap::lbmap contains core functions common to all the lbmap utilities.
=cut

sub new {
    my ($class, %options) = @_;
    my $self = {};
    my %passive;
    $self->{'timeout'}    = $options{'timeout'} ? $options{'timeout'} : 30;
    $self->{'passive'}    = {};
    return bless $self, $class;
}

sub scan {
    my ($self, $target) = @_;
    ($self->{'ssl'}, $self->{'host'}, $self->{'port'}) = $self->_parse_uri($target);
    my $requests = lbmap::Requests->new;
    my $signature = lbmap::Signature->new;
    while ($requests->next) {
        my $response = $self->_request($requests->request);
        foreach my $passive (keys(%{ $self->{'passive'} })) {
            if ($response =~ m/$self->{$passive}{'regex'}/) {
                $self->{$passive}{'callback'}->($response);
            }
        }
        # print $response;
        $signature->add_response($response);
    }
    return $signature->signature();;
}

sub add_passive_detect {
    my ($self, $name, $regex, $function) = @_;
    my ($package, $filename, $line) = caller;
    if (exists($self->{'passive'}{$name})) {
        warn "Overriding existing passive detection $name from $filename line: $line\n";
    }
    $self->{'passive'}{$name}{'regex'} = $regex;
    $self->{'passive'}{$name}{'callback'} = "package::$function";
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
        eval {
        local $SIG{ALRM} = sub { die "TIMEOUT\n"; };
        alarm $self->{'timeout'};
        #eval {
            my $socket = $self->{'socket'};
            # print "Sending $request through $socket\n";
            print $socket $request;
            while (<$socket>) {
                $response .= $_;
            }
        #};
        alarm 0;
        };
        if ($@) {
                die unless ( $@ eq "TIMEOUT\n" );
        }
    }
    return $response;
}

sub _connect {
    my ($self) = shift;
    undef $self->{'socket'};
    if ($self->{'ssl'}) {
        $self->{'socket'} = IO::Socket::SSL->new(PeerAddr => "$self->{'host'}:$self->{'port'}", Timeout => 10);
    } else {
        $self->{'socket'} = IO::Socket::INET->new(PeerAddr => "$self->{'host'}:$self->{'port'}", Timeout => 10);
    }
    # Should probably retry a few times before giving up
    die "Unable to connect to $self->{'host'}:$self->{'port'}\n" unless $self->{'socket'};
    return 1 if $self->{'socket'};
}

1;
