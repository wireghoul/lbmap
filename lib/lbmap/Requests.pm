package lbmap::Requests;

use strict;
use warnings;

=head1 NAME

lbmap::Requests - Request database for HTTP fuzzing

=head1 VERSION

Version 0.1

=cut

# Globals
my @reqs;

=head1 SYNOPSIS

    use lbmap::Requests

    my $foo = lbmap::requests->new();
    print $foo->request;
    $foo->next;
    print $foo->request;

=head1 DESCRIPTION
lbmap::Requests iterates through a database of requests. 
=cut

sub new {
    my ($class, $host, $path) = @_;
    my $self = {};
    $self->{'host'} = $host;
    $self->{'path'} = $path;
    $self->{'_rindex'} = -1; #Lazy fix to avoid off by one issues with while (lbmap::Request->next) invocation
    my $obj =bless $self, $class;
    $obj->populate_reqs;
    return $obj;
}

sub request {
    my $self = shift;
    $self->{'_rindex'} = 0 if ($self->{'_rindex'} == -1);
    if ($self->{'_rindex'} < scalar(@reqs)) {
        return $reqs[ $self->{'_rindex'} ];
    } else {
        return;
    }
}

sub next {
    my $self = shift;
    $self->{'_rindex'} += 1;
    if ($self->{'_rindex'} < scalar(@reqs)) {
        return 1;
    } else {
        return 0;
    }
}

sub load {
    my ($self, $file) = @_;
    if ( -e $file) {
        require $file;
        return 1;
    }
    return 0;
}

sub populate_reqs {
    my $self = shift;
    my $path = $self->{'path'};
    # Subset of requests, needs tuning
    @reqs = (
        "GET $path HTTP/1.0\r\nConnection: Close\r\nHost: $self->{'host'}\r\nUser-Agent: Mozilla/4.0\r\n\r\n",
        "GET $path HTTP/1.0\nConnection: Close\n\n",
        "GET $path HTTP/1.0\rConnection: Close\r\r",
        " \r\n\r\n",
        "$path\r\n\r\n",
        "GET $path\r\n\r\n",
        "GET $path" . "lbmap" x 200 . " HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET $path" . "lbmap" x 2000 . " HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "LBMAP $path HTTP/1.1\r\nConnection: Close\r\nHost: $self->{'host'}\r\n\r\n",
        "%47%45%54 $path HTTP/1.0\r\nConnection: Close\r\nHost: $self->{'host'}\r\n\r\n",
        "ALL YOUR BASE ARE BELONG TO US\r\nConnection: Close\r\n\r\n",
        "GET $path?abc=%GG HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET C:\\ HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET $path FTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET FTP://asdfasdf HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close\r\nContent-Length: 2000000000000000000000000000000000000000\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close\r\nX-Bad header here\r\n\r\n",
        "GET $path HTTP/1.0 X\r\nConnection: Close\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close\r\nLong-Header: " . 'lbmap' x 200 ."\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close\r\nLong-Header: " . 'lbmap' x 1000 . "\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close\r\nLong-Header: " . 'lbmap' x 1800 . "X\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close" . "\r\nX-Many: x" x 50 . "\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close" . "\r\nX-Many: x" x 100 . "\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close" . "\r\nX-Many: x" x 500 . "\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close" . "\r\nX-Many: 0123456789012345678901234567890" x 50 . "\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close" . "\r\nX-Many: 0123456789012345678901234567890" x 100 . "\r\n\r\n",
        "GET $path HTTP/1.0\r\nConnection: Close" . "\r\nX-Many: 0123456789012345678901234567890" x 250 . "\r\n\r\n",
        "OPTIONS $path HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "OPTIONS * HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "OPTIONS #VERB\r\n\r\n",
        "POST $path HTTP/1.0\r\nContent-Length: 1000000000000000000000000000000000000000\r\n\r\n",
        "GET $path HTTP/1.0\r\nMax-Forwards: 3\r\n\r\n",
        "GET $path HTTP/1.0\r\nMax-Forwards: 2\r\n\r\n",
        "GET $path HTTP/1.0\r\nMax-Forwards: 1\r\n\r\n",
        "TRACE $path HTTP/1.0\r\nMax-Forwards: 3\r\n\r\n",
        "TRACE $path HTTP/1.0\r\nMax-Forwards: 2\r\n\r\n",
        "TRACE $path HTTP/1.0\r\nMax-Forwards: 1\r\n\r\n",
      );
    my @all_reqs = (
        " \r\n\r\n",
        "/\r\n\r\n",
        "\0" x 70,
        "\0GET / HTTP/1.0\r\nConnection: Close\r\n\r\n",
        #"\0" x 1000,
        #"\0" x 1000 . "GET / HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "12345 GET / HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "12345 / HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "%47%45%54 / HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "%47ET / HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "ALL YOUR BASE ARE BELONG TO US\r\nConnection: Close\r\n\r\n",
        "GET ~\r\n\r\n",
        "GET /\r\n\r\n",
        "GET\r\n\r\n",
        "GET\0/\0HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET / \0 HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET \0 / HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET \1 HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET%20/ HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET /?abc=%GG HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET C:\ HTTP/1.0\r\nConnection: Close\r\n\r\n",
        "GET / FTP/1.0",
        "GET FTP://asdfasdf HTTP/1.0",
        "GET GET GET",
        "GET / H",
        "GET / HHTP/1.0",
        "GET / hhtp/999.99",
        "GET / HHTP/999.99",
        "GET / HTP/1.0",
        "GET / HTTP/",
        "GET / HTTP/0.9",
        "GET / HTTP / 1",
        "GET / HTTP/1.",
        "get / http;/1.0",
        "Get / HTTP/1.0",
        '""GET / HTTP/1.0',
        '"GET / HTTP/1.0',
        '"GET / HTTP/1.0\"',
        '"GET" / HTTP/1.0',
        'GET "/" HTTP/1.0',
        " GET / HTTP/1.0",
        "G E T / HTTP/1.0",
        "GET `/` HTTP/1.0",
        "GET       /       HTTP/1.0",
        "GET ! HTTP/1.0",
        "GET ? HTTP/1.0",
        "GET / HTTP /1.0",
        "GET / HTTP/1,0",
        "GET / HTTP/1.0",
        "GET // HTTP/1.0",
        "GET /HTTP/1.0",
        "GET . HTTP/1.0",
        "GET '/' HTTP/1.0",
        "GET \ HTTP/1.0",
        "GET \"/\" HTTP/1.0",
        "GET/ HTTP/1.0",
        "GET/HTTP /1.0",
        "GET/HTTP/1 .0",
        "GET/HTTP/1. 0",
        "GET/HTTP/1.0 ",
        "GET/HTTP/1.0",
        "GET / HTTP/1.0\0",
        "GET / HTTP/1.0\n\n",
        "GET / HTTP/1.0\r\nContent-Length: 2000000000000000000000000000000000000000",
        "GET / HTTP/1.0\r\nDate: -1",
        "GET / HTTP/1.0\r\nExpect: 100-continue",
        "GET / HTTP/1.0\r\nMax-Forwards: 0",
        "GET / HTTP/1.0\r\nX-Bad header here",
        "GET / HTTP/1.0 X",
        "GET / HTTP/1.0X",
        "GET / ".'HTTP/1.'.'0' x 1000,
        "GET / HTTP/1.0" . ' ' x 1000,
        "GET / HTTP/1.1.0",
        "GET / HTTP/1.10",
        "GET / HTTP/1.1\r\nHost: localhost",
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: TLS/1.0, HTTP/1.1",
        "GET / HTTP/-1.1\r\nHost: lunch",
        "GET / HTTP/1.1\r\n\r\nHost: localhost",
        "GET / HTTP/1.1\r\nUpgrade: HTTP/1.0",
        "GET / HTTP/1.0\r\nLong-Header: " . 'A' x 1000,
        "GET / HTTP/1.0\r\nLong-Header: " . 'A' x 5000,
        "GET / HTTP/1.0\r\nLong-Header: " . 'A' x 9001,
        "GET / HTTP/1.0" . "\r\nX-a: b" x 10,
        "GET / HTTP/1.2",
        "GET / HTTP/1.X",
        "GET / ".'HTTP/'.'1' x 1000 .'.0',
        "GET / ".'HTTP/1'.'.' x 1000 .'0',
        "GET / HTTP/2.1",
        "GET / http/999.99",
        "GET / HTTP/999.99",
        "GET / HTTP/9.Q",
        "GET / HTTP/FF.DD\r\nHost: lunch",
        "GET / HTTP/Q.9",
        "GET / HTTP/Q.Q",
        "GET http://www.somehost.com/path/file.html HTTP/1.2",
        "GET http://www.somehost.com/path/file.html HTTP/1.2\r\nHost: www.somehost.com",
        "GET / ".'HTTP'.'/' x 1000 .'1.0',
        "GET / ".'H' x 1000 .'TTP/1.0',
        "GET / index.html HTTP/1.0",
        "GET index.html HTTP/1.0",
        "GET /kjsadkjsadkfjaslfjasljdisjadfijqfakckljdkl HTTP/1.0",
        "GETS /index.php",
        "GET\t/\tHTTP/1.0",
        "GET /".' ' x 1000 .'HTTP/1.0',
        "GET ".'/' x 1000 . ' HTTP/1.0',
        "GET".' ' x 1000 . '/ HTTP/1.0',
        "GEX\bT / HTTP/1.0",
        "HEAD /",
        "HEAD /asdfasdfasdfasdfasdf/.. HTTP/1.0",
        "HEAD /asdfasdfasdfasdfasdf/../ HTTP/1.0",
        "HEAD h HTTP/1.0",
        "HEAD / HQWERTY/1.0",
        "HEAD * HTTP/0.1",
        "Head / HTTP/1.0",
        " HEAD / HTTP/1.0",
        "HEAD / HTTP/1.0",
        "HEAD ///////////// HTTP/1.0",
        "HEAD /./././././././././././././././ HTTP/1.0",
        "HEAD /.. HTTP/1.0",
        "HEAD /../ HTTP/1.0",
        "HEAD /../../../../../ HTTP/1.0",
        "HEAD /.\\ HTTP/1.0",
        "HEAD .. HTTP/1.0",
        "HEAD http HTTP/1.0",
        "HEAD http: HTTP/1.0",
        "HEAD http:/ HTTP/1.0",
        "HEAD http:// HTTP/1.0",
        "HEAD HTTP://qwerty.asdfg.com/ HTTP/1.0",
        "HEAD /././././././qwerty/.././././././././ HTTP/1.0",
        "HEAD SHOULDERS KNEES AND TOES",
        "HEAD\t/\tHTTP/1.0",
        "HELLO",
        "HTTP/1.0 / GET",
        " \nHEAD / HTTP/1.0",
        "\nHEAD / HTTP/1.0",
        "OPTIONS /",
        "OPTIONS / HTTP/1.0",
        "OPTIONS * HTTP/1.0",
        "OPTIONS / VERB",
        "OPTIONS #VERB",
        "PING / PONG",
        "POST /",
        "POST / HTTP/1.0",
        "POST / HTTP/1.0\r\nContent-Length: 1000000000000000000000000000000000000000",
        "PUT /",
        "PUT / HTTP/1.0",
        "\r\n" x 1000 . 'GET / HTTP/1.0',
        "TRACE /",
        "TRACE / HTTP/1.0",
        "TRACK /",
        "TRACK / HTTP/1.0",
        " " x 1000,
        "/" x 1000,
        " " x 1000 . 'GET / HTTP/1.0',
      );
};

1;
