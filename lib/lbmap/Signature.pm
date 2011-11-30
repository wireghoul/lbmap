package lbmap::Signature;

use strict;
use warnings;

=head1 NAME

lbmap::Signature - Create machine comparable signatures from http fuzzing

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';
my $_known_signatures;
my $_conversion_table;
=head1 SYNOPSIS

    use lbmap::Signature

    my $foo = lbmap::Signature->new();
    $foo->add_response($raw_http_response);
    print $foo->signature();
    print $foo->identify();

=head1 DESCRIPTION
lbmap::Signature converts HTTP responses to an internal representation of the response, resulting in a short string representing 
=cut

sub new {
    my ($class) = @_;
    my $self = {};
    $self->{'signature'} = '';
    return bless $self, $class;
}


sub add_response {
    my ($self, $http_response) = @_;
    #my ($headers, $body);
    my $code = ' ';
    if ($http_response =~ /^(HTTP\/...) (...) (.*)?\r\n/) {
	$code = $2;
    } elsif ($http_response eq '') {
        $code = '';
    }
    # Defaults to 0.9 response (code = ' ') if neither condition matches <- Bug?
    if (exists($_conversion_table->{$code})) {
        $self->{'signature'} .= $_conversion_table->{$code};
        if ($code eq '503') {
            #warn "Received 503 error - Signature may not be reliable\n";
        }
    } else {
	warn "Unknown: $1 $2 $3\n";
        $self->{'signature'} .= '?';
    }
}

sub add_timeout {
    my $self = shift;
    $self->{'signature'} .= '!';
}

sub identify {
    my $self = shift;
    foreach my $sig (keys(%{ $_known_signatures })) {
        if ($self->{'signature'} =~ $_known_signatures->{$sig}) {
            return $sig;
        }
    }
}

sub signature {
    my $self = shift;
    return $self->{'signature'};
}

# Leave this at bottom for readability
sub BEGIN {
    # Load known signatures
    $_known_signatures = {
        'Apache1' => '',
        'Apache2' => '',
        'pound' => '',
    };
    # TODO: Sort this by response code
    $_conversion_table = {
        '' => '0',
        ' ' => '9',
        '100' => '1', # 100 continue
        '200' => 'a', # OK
        '301' => 'a', # Permanent redirect
        '302' => 'a', # Temporary redirect
        '404' => 'a', # Page not found
        '500' => 'X', # Internal server error
        '503' => 'x', # Usually means missing backend server
        '403' => 'A', # Denied
        '501' => 'D', # Method not implemented
	'405' => 'C', # Method not allowed
	'400' => 'B', # Bad request (parser)
        '502' => 't', # Unable to contact gateway
	'413' => 'l', # Request entity too long
	'414' => 'L', # Request URI too long
        '411' => 'n', # Length required
    };
}
         
1;
