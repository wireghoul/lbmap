package lbmap::Passive::Content;

use strict;
use warnings;
use lbmap::lbmap;
use Digest::MD5 qw(md5_hex);

=head1 NAME

lbmap::Passive::Content - Detects default content

=head1 VERSION

Version 0.1

=cut

# Globals
our $VERSION = '0.1';
our $AUTHOR = 'Eldar Marcussen - http://www.justanotherhacker.com';
our %sigmap;

=head1 DESCRIPTION
lbmap::Passive::Content detects default content
=cut

sub new {
    my ($class, $parent) = @_;
    my $self = {};
    $self->{'parent'} = $parent;
    bless $self, $class;
    &load_content_map;
    $self->{'parent'}->add_passive_detect('Default content', "\r\n\r\n", \&detect_default_content );
    return $self;
}


sub detect_default_content {
    my ($parent, $http_response) = @_;
    my ($headers, $content) = split /\r\n\r\n/, $http_response;
    my $content_sig = md5_hex($content);
    print "---DBG---\n$headers\n----".substr($content,0,1024)."\n===$content_sig===\n" if $parent->{'debug'};
    if (exists($sigmap{$content_sig})) {
        $parent->add_result($sigmap{$content_sig}[0], $sigmap{$content_sig}[1]);
    }
}

sub load_content_map {
    %sigmap = (
        # Pound
        'e538c3e27513ab2815dfcc064f6a0c35' => ['loadbalancer', 'Pound'], #Request URI too long
        '0ccc2c7f754ede7fe3d90f100ea84993' => ['loadbalancer', 'Pound'], #This method may not be used
        '9458e7e0a9e562a598afab0506c9afce' => ['loadbalancer', 'Pound'], #An internal server error occured
        # haproxy
        '5f95e6fcd26fb7196232fac3c448c461' => ['loadbalancer', 'haproxy'], # 400 invalid request
        # Varnish
        # Kemp
        'af373923bc4deb3e56fbbc815abfddfb' => ['loadbalancer', 'Kemp'], #400 Invalid Request
        'b2db01766e72f470d049e4ea21e96e17' => ['loadbalancer', 'Kemp'], #411 Invalid Request
        '90833dac2eb2b8f1efca0ca11fb4505d' => ['loadbalancer', 'Kemp'], #501 Invalid Request
        # Apache
        'd38bed70399fd9cdc066cac1604bc961' => ['webserver', 'Apache'], # The number of request header fields exceeds this server's limit.
        'e946fd60df0e24f957bd539c00d6f91d' => ['webserver', 'Apache'], # Your browser sent a request that this server could not understand.
        '8cd03225fec9516436c561697d9d2ec2' => ['webserver', 'Apache'], # TRACE not allowed for URL /
        '5b82d4f6ec99bd437fe81065061e111f' => ['webserver', 'Apache'], # Request Entity Too Large (POST)
        '34abf822831d2ee93ebf0dfa3db058ee' => ['webserver', 'Apache'], # Request Entity Too Large (GET)
        # IIS
        '02c5242bd2adc73d4984a15ef7a108b3' => ['webserver', 'IIS'], # Error 400. The VERB is invalid
        '6c13efb22d910e0bcfa6d3f58d5716ab' => ['webserver', 'IIS'], # Error 400. The request is badly formed
        '93b17548f8f23ad8a33060f706baca1d' => ['webserver', 'IIS'], # Error 400. The request URL is invalid
        '42006f6a9ef6f30f466e2d2ee281b197' => ['webserver', 'IIS'], # Request entity too large
        # WebSphere
        '5d8385bf82de001a2bf8b09735c8d99b' => ['webserver', 'IBM WebSphere'], # SRVE0190E: File not found
        '928372a09abc954d3e405013589acf76' => ['webserver', 'IBM WebSphere'], # SRVE0190E: File not found chunked encoding
        # etc
    );
}

1;
