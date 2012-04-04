package lbmap::Passive::BigIP;

use strict;
use warnings;

=head1 NAME

lbmap::Passive::BigIP - Decodes F5 BIGIP cookie data to enumerate backends and more

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';
=head1 SYNOPSIS

    use lbmap::Passive::BigIP;

    my $foo = lbmap::Passive::BigIP->new();
    $foo->decode_response($raw_http_response);
    if ($foo->info()) {
      print $foo->info();
    }

=head1 DESCRIPTION
lbmap::Passive::BigIP decodes F5 BIGIP cookies, such as persistent pool information or routes. 
=cut

sub new {
    my ($class) = @_;
    my $self = {};
    return bless $self, $class;
}


sub decode_response {
    my ($self, $http_response) = @_;
}

sub info {
    my $self = shift;
}

1;
