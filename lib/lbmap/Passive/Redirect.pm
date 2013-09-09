package lbmap::Passive::Redirect;

use strict;
use warnings;
use lbmap::lbmap;

=head1 NAME

lbmap::Passive::Redirect - Detects redirection urls in server response

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';

=head1 DESCRIPTION
lbmap::Passive::Redirect detects location headers
=cut

sub new {
    my ($class, $parent) = @_;
    my $self = {};
    $self->{'parent'} = $parent;
    bless $self, $class;
    $self->{'parent'}->add_passive_detect('Location_header', 'Location: .*', \&detect_server_header );
    return $self;
}

sub detect_server_header {
    my ($parent, $http_response) = @_;
    if ($http_response =~ m/Location: (.*)\r\n/o) {
        $parent->add_result('Redirection', $1);
    }
}

1;
