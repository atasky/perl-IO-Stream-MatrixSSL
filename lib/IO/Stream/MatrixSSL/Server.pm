package IO::Stream::MatrixSSL::Server;
use 5.010001;
use warnings;
use strict;
use utf8;
use Carp;

our $VERSION = 'v1.1.2';

use IO::Stream::const;
use IO::Stream::MatrixSSL::const;
use Crypt::MatrixSSL 1.83;
use Scalar::Util qw( weaken );

use parent qw( -norequire IO::Stream::MatrixSSL );

sub new {
    my ($class, $opt) = @_;
    croak '{crt} and {key} required'
        if !defined $opt->{crt} || !defined $opt->{key};
    my $self = bless {
        crt         => undef,       # filename(s) with server's certificate(s)
        key         => undef,       # filename with server's private key
        pass        => undef,       # password to decrypt private key
        trusted_CA  => undef,       # filename(s) with trusted root CA cert(s)
        cb          => undef,       # callback for validating certificate
        %{$opt},
        out_buf     => q{},                 # modified on: OUT
        out_pos     => undef,               # modified on: OUT
        out_bytes   => 0,                   # modified on: OUT
        in_buf      => q{},                 # modified on: IN
        in_bytes    => 0,                   # modified on: IN
        ip          => undef,               # modified on: RESOLVED
        is_eof      => undef,               # modified on: EOF
        _param      => [],          # param for cb
        _ssl        => undef,       # MatrixSSL 'session' object
        _ssl_keys   => undef,       # MatrixSSL 'keys' object
        _handshaked => 0,           # flag, will be true after handshake
        _want_write => undef,
        _t          => undef,
        _cb_t       => undef,
        }, $class;
    weaken(my $this = $self);
    $self->{_cb_t} = sub { $this->T() };
    # Initialize SSL.
    # TODO OPTIMIZATION Cache {_ssl_keys}.
    matrixSslReadKeys($self->{_ssl_keys}, $self->{crt}, $self->{key},
        $self->{pass}, $self->{trusted_CA})
        == 0 or croak 'matrixSslReadKeys: wrong {crt}, {key}, {pass} or {trusted_CA}?';
    my $flags = $SSL_FLAGS_SERVER;
    if (defined $self->{trusted_CA}) {
        $flags |= $SSL_FLAGS_CLIENT_AUTH;
    }
    matrixSslNewSession($self->{_ssl}, $self->{_ssl_keys},
        undef, $flags)
        == 0 or croak 'matrixSslNewSession';
    # Prepare first param for cb.
    weaken($self->{_param}[0] = $self);
    if (defined $self->{cb}) {
        matrixSslSetCertValidator($self->{_ssl}, $self->{cb}, $self->{_param});
    }
    return $self;
}

sub PREPARE {
    my ($self, $fh, $host, $port) = @_;
    if (!defined $host) {   # ... else timer will be set on CONNECTED
        $self->{_t} = EV::timer(TOHANDSHAKE, 0, $self->{_cb_t});
    }
    # Prepare second param for cb.
    my $io = $self;
    while ($io->{_master}) {
        $io = $io->{_master};
    }
    weaken($self->{_param}[1] = $io);
    $self->{_slave}->PREPARE($fh, $host, $port);
    return;
}


1;
