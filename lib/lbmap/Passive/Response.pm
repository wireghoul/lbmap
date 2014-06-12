package lbmap::Passive::Response;

use strict;
use warnings;
use lbmap::lbmap;

=head1 NAME

lbmap::Passive::Response - Detects HTTP/1.x response strings

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';
our %sigmap;

=head1 DESCRIPTION
lbmap::Passive::Response detects known HTTP/1.x response strings
=cut

sub new {
    my ($class, $parent) = @_;
    my $self = {};
    $self->{'parent'} = $parent;
    bless $self, $class;
    &load_content_map;
    $self->{'parent'}->add_passive_detect('HTTP Response codes', "HTTP/1", \&detect_response_codes );
    return $self;
}


sub detect_response_codes {
    my ($parent, $http_response) = @_;
    $http_response =~ m!(HTTP/1.*)[\r\n]!o; # Either \r or \n cause not all servers are compliant to CRLF
    my $response_code = $1;
    print "Responz: $http_response\n" if $parent->{'debug'};
    if (exists($sigmap{$response_code})) {
        $parent->add_result('HTTP Match', $sigmap{$response_code});
    }
}

sub load_content_map {
    %sigmap = (
        # Apache
        'HTTP/1.1 414 Request-URI Too Large' => 'Apache',
        'HTTP/1.1 501 Method Not Implemented' => 'Apache',
        # IIS
        'HTTP/1.1 501 Not Implemented' => 'IIS',
        'HTTP/1.1 500 URL Rewrite Module Error.' => 'IIS',
        # haproxy
        'HTTP/1.0 400 Bad request' => 'haproxy',
        # Pound
        'HTTP/1.0 414 Request URI too long' => 'Pound',
        # Kemp
        'HTTP/1.1 400 Invalid Request' => 'Kemp',
        'HTTP/1.1 411 Invalid Request' => 'Kemp',
        'HTTP/1.1 501 Invalid Request' => 'Kemp',
        # etc
        'HTTP/1.1 596 596' => 'Mashery Proxy', #Request URI too long
    );
}

1;
