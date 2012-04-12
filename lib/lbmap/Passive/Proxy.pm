package lbmap::Passive::Via;

use strict;
use warnings;
use lbmap::lbmap;

=head1 NAME

lbmap::Passive::Via - Detects Via proxy headers

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';

=head1 DESCRIPTION
lbmap::Passive::Via detects Via proxy headers
=cut

sub new {
    my ($class, $parent) = @_;
    my $self = {};
    $self->{'parent'} = $parent;
    bless $self, $class;
    $self->{'parent'}->add_passive_detect('Via_header', 'Via: .*', \&detect_via_header );
    return $self;
}


sub detact_via_header {
    my ($parent, $http_response) = @_;
    if ($http_response =~ m/Via: (.*)/o) {
        $parent->add_result('reverseproxy', $1);
    }
}

1;
