package lbmap::lbmap;

use strict;
use warnings;
use IO::Socket::INET;
use IO::Socket::SSL;;
use lbmap::Requests;
use lbmap::Signature;
use Data::Dumper;

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
    $self->{'debug'}      = $options{'debug'} ? $options{'debug'} : 0;
    $self->{'timeout'}    = $options{'timeout'} ? $options{'timeout'} : 30;
    $self->{'reconnect'}  = $options{'reconnect'} ? $options{'reconnect'} : 3;
    $self->{'passive'}    = {};
    $self->{'result'}   = {};
    if ($self->{'debug'}) {
        print "Debug enabled\n";
    }
    bless $self, $class;
    $self->_load_passive;
    return $self;
}

sub scan {
    my ($self, $target) = @_;
    my %result;
    print "Starting scan\n" if $self->{'debug'};
    ($self->{'ssl'}, $self->{'host'}, $self->{'port'}) = $self->_parse_uri($target);
    my $requests = lbmap::Requests->new;
    my $signature = lbmap::Signature->new;
    while ($requests->next) {
        print "Sending request [".$requests->{'_rindex'} ."]\n" if $self->{'debug'};
        my $response = $self->_request($requests->request);
        print "Got response\n" if $self->{'debug'};
        foreach my $name (keys(%{ $self->{'passive'} })) {
            print "Processing plugin $name\n" if $self->{'debug'};
            if ($response =~ m/$self->{'passive'}{$name}{'regex'}/) {
                print "Issuing callback for plugin $name\n" if $self->{'debug'};
                $self->{'passive'}{$name}{'callback'}->($self, $response);
            }
        }
        print "Processing signature\n" if $self->{'debug'};
        $signature->add_response($response);
    }
    print " done\n" if $self->{'debug'};
    $signature->process($self); #Should probably be more elegant
    %result = %{ $self->{'result'} };
    $result{'signature'}  = $signature->signature();
    $result{'target'} = $target;
    print "Result object:\n".Dumper(%result) if $self->{'debug'};
    return %result;
}

sub enumerate {
    my ($self, $target) = @_;
}

sub add_passive_detect {
    my ($self, $name, $regex, $function) = @_;
    my ($package, $filename, $line) = caller;
    if (exists($self->{'passive'}{$name})) {
        warn "Overriding existing passive detection $name from $filename line: $line\n";
    }
    $self->{'passive'}{$name}{'regex'} = $regex;
    $self->{'passive'}{$name}{'callback'} = $function;
    return 1;
}

sub add_result {
    my ($self, $category, $value) = @_;
    $self->{'result'}{$category}{$value}++;
}

sub _parse_uri {
    my ($self, $uri) = @_;
    my @p = (0, '', 80); #Defaults
    # Quick fix to handle uri's without protocol designation
    $uri = "http://$uri" if ($uri !~ m!://!);
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
            local $SIG{PIPE} = 'IGNORE'; # Dirty hack to avoid silent exit if server closed socket`
            local $SIG{ALRM} = sub { die "TIMEOUT\n"; };
            alarm $self->{'timeout'};
            my $socket = $self->{'socket'};
            print $socket $request;
            while (<$socket>) {
                $response .= $_;
            }
            alarm 0;
        };
        if ($@) {
                die $@ unless ( $@ eq "TIMEOUT\n" );
        }
    }
    return $response;
}

sub _connect {
    my ($self) = shift;
    undef $self->{'socket'};
    my $attempt = 0;
    while ($attempt < $self->{'reconnect'}) {
        if ($self->{'ssl'}) {
            $self->{'socket'} = IO::Socket::SSL->new(PeerAddr => "$self->{'host'}:$self->{'port'}", Timeout => 10);
        } else {
            $self->{'socket'} = IO::Socket::INET->new(PeerAddr => "$self->{'host'}:$self->{'port'}", Timeout => 10);
        }
        return 1 if $self->{'socket'};
        $attempt++;
        warn "Unable to connect to $self->{'host'}:$self->{'port'} try #$attempt ... retrying\n";
    }
    die "Can't connect ... exiting\n";
}

sub _load_passive {
    my $self = shift;
    #foreach my $plugin (glob "./lib/lbmap/Passive/*.pm") {
    #    require $plugin;
    #}
    # Hard coded reference to test callbacks
    use lbmap::Passive::BigIP;
    my $bigip = lbmap::Passive::BigIP->new($self);
    use lbmap::Passive::Proxy;
    my $via = lbmap::Passive::Proxy->new($self);
    use lbmap::Passive::Server;
    my $server = lbmap::Passive::Server->new($self);
    use lbmap::Passive::Redirect;
    my $redirect = lbmap::Passive::Redirect->new($self);
}

1;
