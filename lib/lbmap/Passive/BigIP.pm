package lbmap::Passive::BigIP;

use strict;
use warnings;
use lbmap::lbmap;

=head1 NAME

lbmap::Passive::BigIP - Decodes F5 BIGIP cookie data to enumerate backends and more

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';

=head1 DESCRIPTION
lbmap::Passive::BigIP decodes F5 BIGIP cookies, such as persistent pool information or routes. 
=cut

sub new {
    my ($class, $parent) = @_;
    my $self = {};
    $self->{'parent'} = $parent;
    bless $self, $class;
    $self->{'parent'}->add_passive_detect('test', 'Server: .*', \&decode_bigip );
    return $self;
}


sub decode_bigip {
    my ($parent, $http_response) = @_;
    if ($http_response =~ m/Set-Cookie: (BIGip.*)=(\d+)\.(\d+)\.(\d+)/o) {
        my ($pool, $host, $port, $wat) = ($1, $2, $3, $4);
        my $backend = join ".", map {hex} reverse ((sprintf "%08x", $host) =~ /../g);
        $backend.=":".hex join "", reverse((sprintf "%02x", $port) =~ /../g);
        $parent->add_backend($backend);
    }
}

1;
