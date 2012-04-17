package lbmap::Passive::Proxy;

use strict;
use warnings;
use lbmap::lbmap;

=head1 NAME

lbmap::Passive::Proxy - Detects proxy headers

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';

=head1 DESCRIPTION
lbmap::Passive::Proxy detects proxy headers
=cut

sub new {
    my ($class, $parent) = @_;
    my $self = {};
    $self->{'parent'} = $parent;
    bless $self, $class;
    $self->{'parent'}->add_passive_detect('Via_header', 'Via: .*', \&detect_via_header );
    $self->{'parent'}->add_passive_detect('Proxy_header', '[pP]roxy.*', \&detect_proxy_header );
    return $self;
}


sub detect_via_header {
    my ($parent, $http_response) = @_;
    if ($http_response =~ m/\nVia: (.*)\r\n/o) {
        $parent->add_result('reverseproxy', $1);
    }
}

sub detect_proxy_header {
    my ($parent, $http_response) = @_;
    if ($http_response =~ m/ProxyServer: (.*)\r\n/o) {
        $parent->add_result('proxyserver', $1 );
    }
}

1;
