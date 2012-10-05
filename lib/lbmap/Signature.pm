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
    $self->{'signature'} = '01';
    return bless $self, $class;
}


sub add_response {
    my ($self, $http_response) = @_;
    my $code = ' ';
    my $http_version = '0.9';
    if ($http_response =~ /^(HTTP\/...) (...) (.*)?\r\n/) {
	$code = $2;
	$http_version = $1;
    } elsif ($http_response eq '') {
        $code = '';
    }
    # Defaults to 0.9 response (code = ' ') if neither condition matches
    if (exists($_conversion_table->{$code})) {
        my $rcode = $_conversion_table->{$code};
        if ($http_version eq 'HTTP/1.1') {
            $rcode = uc($rcode);
        }
        $self->{'signature'} .= $rcode;
        if ($code eq '503') {
           warn "Received 503 error - Signature may not be reliable\n";
        }
    } else {
	warn "Unknown: $1 $2 $3\n";
        $self->{'signature'} .= '??';
    }
}


sub add_timeout {
    my $self = shift;
    $self->{'signature'} .= '!!';
}

sub process {
    my ($self, $parent) = @_;
    foreach my $sig (keys(%{ $_known_signatures })) {
        if ($self->{'signature'} =~ m/^$_known_signatures->{$sig}$/) {
            $parent->add_result('signaturematch', $sig);
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
	'F5 WAF' =>	'01BCBC--A0--99A0BCA0BCA0BCA0BCBCBCBCBCBCBCBCBCBCBCBCBCA0A0--',
        'Apache' =>	'01A0A0--999999BCD1BCA0A0A0A0L3BCA0A0A0BCA0BCBCA0BCBCA0A099TT',
        'pound' =>	'01A0A0--d1d1d1d1d1d1A0A0d1A0--A0d1A0A0A0A0BCx0A0BCx0d1d1d1--',
        'haproxy' =>	'01A0A0bcbcbcA0bcD1bcA0A0bcA0L3bcbcA0A0bcA0BCbcA0BCbcA0A0A0--',
        'varnish' =>	'01A0A0------A0BCD1BCA0A0A0A0A0A0A0A0A0--A0BCBCA0BC--A0A0X3--',
    };
    # TODO: Sort this by response code
    $_conversion_table = {
        '' => '--',
        ' ' => '99',
        '100' => 'cc', # 100 continue
        '200' => 'a0', # OK
        '301' => 'a1', # Permanent redirect
        '302' => 'a2', # Temporary redirect
	'303' => 'a3', # Redirect to GET
        '404' => 'a4', # Page not found
        '500' => 'x0', # Internal server error
        '503' => 'x3', # Usually means missing backend server
        '403' => 'd3', # Denied
        '501' => 'd1', # Method not implemented
	'405' => 'd5', # Method not allowed
	'400' => 'bc', # Bad request (parser)
        '502' => 'x2', # Unable to contact gateway
	'505' => 'x5', # HTTP version not supported
        '408' => 'tt', # Timeout (Incomplete request)
	'413' => 'l3', # Request entity too long
	'414' => 'l4', # Request URI too long
        '411' => 'lr', # Length required
    };
}
         
1;
