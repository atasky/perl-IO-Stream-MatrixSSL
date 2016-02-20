package IO::Stream::MatrixSSL::const;
use 5.010001;
use warnings;
use strict;
use utf8;
use Carp;

our $VERSION = 'v1.1.2';

# Timeouts:
use constant TOHANDSHAKE    => 30;

# Custom errors:
use constant ETOHANDSHAKE   => 'ssl handshake timeout';


sub import {
    my $pkg = caller;
    no strict 'refs';
    for my $const (qw( TOHANDSHAKE ETOHANDSHAKE )) {
        *{"${pkg}::$const"} = \&{$const};
    }
    return;
}


1;
