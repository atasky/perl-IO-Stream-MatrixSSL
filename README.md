[![Build Status](https://travis-ci.org/powerman/perl-IO-Stream-MatrixSSL.svg?branch=master)](https://travis-ci.org/powerman/perl-IO-Stream-MatrixSSL)
[![Coverage Status](https://coveralls.io/repos/powerman/perl-IO-Stream-MatrixSSL/badge.svg?branch=master)](https://coveralls.io/r/powerman/perl-IO-Stream-MatrixSSL?branch=master)

# NAME

IO::Stream::MatrixSSL - Crypt::MatrixSSL plugin for IO::Stream

# VERSION

This document describes IO::Stream::MatrixSSL version v1.1.2

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
        my ($certs, $ssl, $stream) = ($_[0], @{ $_[1] });
        # check cert, for ex.: $certs->[0]{subject}{commonName}
        return 0;
    }

# DESCRIPTION

This module is plugin for IO::Stream which allow you to use SSL (on both
client and server streams).

# INTERFACE 

- IO::Stream::MatrixSSL::Client->new(\\%opt)

    Create and return new IO::Stream plugin object.

    There two optional parameters:

    - cb

        This should be CODE ref to your callback, which should check server
        certificate. Callback will be called with two parameters: HASH ref with
        certificate details, and ARRAY ref with two elements:
        IO::Stream::MatrixSSL::Client object and IO::Stream object (see [SYNOPSIS](https://metacpan.org/pod/SYNOPSIS)
        for example).

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

    - trusted\_CA

        This should be name of file (or files) with allowed CA certificates,
        required to check RSA signature of server certificate. This module
        installed with such file, so chances are you doesn't need to change
        default {trusted\_CA} value if you just wanna connect to https servers.

        There may be many files listed in {trusted\_CA}, separated by ";".
        Each file can contain many CA certificates.

- IO::Stream::MatrixSSL::Server->new(\\%opt)

    Create and return new IO::Stream plugin object.

    There at least two required parameters: {crt} and {key}. If {key} is
    encrypted, then one more parameter required: {pass}.

    - crt

        This should be name of file (or files) with server certificate (or chain
        of certificates). See above {trusted\_CA} about format of this parameter.

    - key

        This should be name of file with private key file for server certificate
        (file should be in PEM format).

    - pass

        If file with private key is encrypted, you should provide password for
        decrypting it in this parameter.

# DIAGNOSTICS

## IO::Stream::MatrixSSL::Client

- `matrixSslReadKeys: wrong {trusted_CA}?`

    File with trusted CA certificates can't be read. If you provide own file,
    there some problem with it. If you doesn't provided own file, then probably
    this module was installed incorrectly - there should be default file with
    trusted CA certificates (taken from Mozilla) installed with module.

- `matrixSslNewSession: wrong {_ssl_session}?`

    This error shouldn't happens, it mean there some bug in this module,
    or Crypt::MatrixSSL, or MatrixSSL itself.

- `matrixSslEncodeClientHello`

    This error shouldn't happens, it mean there some bug in this module,
    or Crypt::MatrixSSL, or MatrixSSL itself.

## IO::Stream::MatrixSSL::Server

- `{crt} and {key} required`

    You can't create SSL server without certificate and key files.

- `matrixSslReadKeys: wrong {crt}, {key} or {pass}?`

    Certificate and key files you provided can't be read by MatrixSSL,
    or may be you used wrong password for key file.

- `matrixSslNewSession`

    This error shouldn't happens, it mean there some bug in this module,
    or Crypt::MatrixSSL, or MatrixSSL itself.

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

This software is Copyright (c) 2008-2016 by Alex Efros &lt;powerman@cpan.org>.

This is free software, licensed under:

    The GNU General Public License version 2

instead of less restrictive MIT only because…

MatrixSSL is distributed under the GNU General Public License…

Crypt::MatrixSSL uses MatrixSSL, and so inherits the same license…

IO::Stream::MatrixSSL uses Crypt::MatrixSSL, and so inherits the same license.

GPL is a virus, avoid it whenever possible!
