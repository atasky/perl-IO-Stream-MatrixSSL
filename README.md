[![Build Status](https://travis-ci.org/powerman/perl-IO-Stream-MatrixSSL.svg?branch=master)](https://travis-ci.org/powerman/perl-IO-Stream-MatrixSSL)
[![Coverage Status](https://coveralls.io/repos/powerman/perl-IO-Stream-MatrixSSL/badge.svg?branch=master)](https://coveralls.io/r/powerman/perl-IO-Stream-MatrixSSL?branch=master)

# NAME

IO::Stream::MatrixSSL - Crypt::MatrixSSL plugin for IO::Stream

# VERSION

This document describes IO::Stream::MatrixSSL version v2.0.0

# SYNOPSIS

    use IO::Stream;
    use IO::Stream::MatrixSSL;

    # SSL server
    IO::Stream->new({
        ...
        plugin => [
            ...
            ssl     => IO::Stream::MatrixSSL::Server->new({
                crt     => 'mysrv.crt',
                key     => 'mysrv.key',
            }),
            ...
        ],
    });

    # SSL client
    IO::Stream->new({
        ...
        plugin => [
            ...
            ssl     => IO::Stream::MatrixSSL::Client->new({
                cb      => \&validate,
            }),
            ...
        ],
    });
    sub validate {
        my ($ssl, $certs) = @_;
        my $stream = $ssl->stream();
        # check cert, for ex.: $certs->[0]{subject}{commonName}
        return 0;
    }

# DESCRIPTION

This module is plugin for IO::Stream which allow you to use SSL (on both
client and server streams).

# INTERFACE

## IO::Stream::MatrixSSL::Client

### new

    $plugin_ssl_client = IO::Stream::MatrixSSL::Client->new();

    $plugin_ssl_client = IO::Stream::MatrixSSL::Client->new({
        crt         => '/path/to/client.crt',
        key         => '/path/to/client.key',
        pass        => 's3cret',
        trusted_CA  => '/path/to/ca-bundle.crt',
        cb          => \&validate,
    });

Create and returns new IO::Stream plugin object.

- crt
- key
- pass

    Authenticate client on server using client's certificate.
    (You'll need Crypt::MatrixSSL3 compiled with support for client authentication.)

    `crt` and `key` should contain file names of client's certificate and
    private key (in PEM format), `pass` should contain password (as string)
    for private key.

    You can provide multiple file names with client's certificates in `crt`
    separated by `;`.

    All optional (`crt` and `key` should be either both provided or both omitted,
    `pass` should be provided only if `key` file protected by password).

- trusted\_CA

    This should be name of file (or files) with allowed CA certificates,
    required to check RSA signature of server certificate. Crypt::MatrixSSL3
    provides such a file, so chances are you doesn't need to change default
    {trusted\_CA} value (`$Crypt::MatrixSSL3::CA_CERTIFICATES`) if you just
    wanna connect to public https servers.

    There may be many files listed in {trusted\_CA}, separated by `;`.
    Each file can contain many CA certificates.

- cb

    This should be CODE ref to your callback, which will check server
    certificate. Callback will be called with two parameters:
    IO::Stream::MatrixSSL::Client (or IO::Stream::MatrixSSL::Server - if
    you're validating client's certificate) object and HASH ref with
    certificate details (see ["SYNOPSIS"](#synopsis) for example).

    Callback should return a number >=0 if this certificate is acceptable,
    and we can continue with SSL handshake, or number <0 if this certificate
    isn't acceptable and we should interrupt this connection and return error
    to IO::Stream user callback. If this function will throw exception, it will
    be handled just as return(-1).

    Hash with certificate details will looks this way:

        verified       => $verified,
        notBefore      => $notBefore,
        notAfter       => $notAfter,
        subjectAltName => {
            dns             => $dns,
            uri             => $uri,
            email           => $email,
            },
        subject        => {
            country         => $country,
            state           => $state,
            locality        => $locality,
            organization    => $organization,
            orgUnit         => $orgUnit,
            commonName      => $commonName,
            },
        issuer         => {
            country         => $country,
            state           => $state,
            locality        => $locality,
            organization    => $organization,
            orgUnit         => $orgUnit,
            commonName      => $commonName,
            },

    where all values are just strings except these:

        $verified
            Status of cetrificate RSA signature check:
            -1  signature is wrong
             1  signature is correct
        $notBefore
        $notAfter
            Time period when certificate is active, in format
            YYYYMMDDHHMMSSZ     (for ex.: 20061231235959Z)

### stream

    $stream = $plugin_ssl_client->stream();

Returns IO::Stream object related to this plugin object.

## IO::Stream::MatrixSSL::Server

Same as above for IO::Stream::MatrixSSL::Client.

# MIGRATION

MatrixSSL often makes incompatible API changes, and so does
Crypt::MatrixSSL3. Sometimes because of this IO::Stream::MatrixSSL also
change API in incompatible way, and below explained how to migrate your
code.

## 1.1.2 to 2.0.0

Parameters for validation callback was changed:

    sub validate {
        ### WAS
        my ($certs, $ssl, $stream) = ($_[0], @{ $_[1] });

        ### NOW
        my ($ssl, $certs) = @_;
        my $stream = $ssl->stream();

        ...
    }

Some error messages was changed too.

# SUPPORT

## Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at [https://github.com/powerman/perl-IO-Stream-MatrixSSL/issues](https://github.com/powerman/perl-IO-Stream-MatrixSSL/issues).
You will be notified automatically of any progress on your issue.

## Source Code

This is open source software. The code repository is available for
public review and contribution under the terms of the license.
Feel free to fork the repository and submit pull requests.

[https://github.com/powerman/perl-IO-Stream-MatrixSSL](https://github.com/powerman/perl-IO-Stream-MatrixSSL)

    git clone https://github.com/powerman/perl-IO-Stream-MatrixSSL.git

## Resources

- MetaCPAN Search

    [https://metacpan.org/search?q=IO-Stream-MatrixSSL](https://metacpan.org/search?q=IO-Stream-MatrixSSL)

- CPAN Ratings

    [http://cpanratings.perl.org/dist/IO-Stream-MatrixSSL](http://cpanratings.perl.org/dist/IO-Stream-MatrixSSL)

- AnnoCPAN: Annotated CPAN documentation

    [http://annocpan.org/dist/IO-Stream-MatrixSSL](http://annocpan.org/dist/IO-Stream-MatrixSSL)

- CPAN Testers Matrix

    [http://matrix.cpantesters.org/?dist=IO-Stream-MatrixSSL](http://matrix.cpantesters.org/?dist=IO-Stream-MatrixSSL)

- CPANTS: A CPAN Testing Service (Kwalitee)

    [http://cpants.cpanauthors.org/dist/IO-Stream-MatrixSSL](http://cpants.cpanauthors.org/dist/IO-Stream-MatrixSSL)

# AUTHOR

Alex Efros &lt;powerman@cpan.org>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2008- by Alex Efros &lt;powerman@cpan.org>.

This is free software, licensed under:

    The GNU General Public License version 2

instead of less restrictive MIT only because…

MatrixSSL is distributed under the GNU General Public License…

Crypt::MatrixSSL3 uses MatrixSSL, and so inherits the same license…

IO::Stream::MatrixSSL uses Crypt::MatrixSSL3, and so inherits the same license.

GPL is a virus, avoid it whenever possible!
