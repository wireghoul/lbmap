package lbmap::Passive::Server;

use strict;
use warnings;
use lbmap::lbmap;

=head1 NAME

lbmap::Passive::Server - Detects web server headers

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';

=head1 DESCRIPTION
lbmap::Passive::Server detects server headers
=cut

sub new {
    my ($class, $parent) = @_;
    my $self = {};
    $self->{'parent'} = $parent;
    bless $self, $class;
    $self->{'parent'}->add_passive_detect('Server_header', 'Server: .*', \&detect_server_header );
    return $self;
}

sub detect_server_header {
    my ($parent, $http_response) = @_;
    if ($http_response =~ m/Server: (.*)\r\n/o) {
        $parent->add_result('webserver', $1);
    }
}

sub detect_etag_header {
    my ($parent, $http_response) = @_;
    if ($http_response =~ m/ETag: ".+-.+-.+"/) {
        $parent->add_result('webserver', 'Apache');
    }
}

1;
