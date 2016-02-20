## no critic (Capitalization)
package IO::Stream::MatrixSSL;
use 5.010001;
use warnings;
use strict;
use utf8;
use Carp;

our $VERSION = 'v1.1.2';

use IO::Stream::const;
use IO::Stream::MatrixSSL::const;
use Crypt::MatrixSSL 1.83;

use IO::Stream::MatrixSSL::Client;
use IO::Stream::MatrixSSL::Server;


sub DESTROY {
    my ($self) = @_;
    # Free memory in MatrixSSL.
    matrixSslDeleteSession($self->{_ssl});
    matrixSslFreeKeys($self->{_ssl_keys});
    return;
}

sub T {
    my ($self) = @_;
    my $m = $self->{_master};
    $m->EVENT(0, ETOHANDSHAKE);
    return;
}

sub WRITE {
    my ($self) = @_;
    if (!$self->{_handshaked}) {
        $self->{_want_write} = 1;
    }
    else {
        my $m = $self->{_master};
        my $s = substr $m->{out_buf}, $m->{out_pos}||0;
        my $n = length $s;
        while (length $s) {
            my $s2 = substr $s, 0, $SSL_MAX_PLAINTEXT_LEN, q{};
            if (matrixSslEncode($self->{_ssl}, $s2, $self->{out_buf}) < 0) {
                $m->EVENT(0, 'matrixSslEncode');
                return;
            }
        }
        if (defined $m->{out_pos}) {
            $m->{out_pos} += $n;
        } else {
            $m->{out_buf} = q{};
        }
        $m->{out_bytes} += $n;
        $m->EVENT(OUT);
        $self->{_slave}->WRITE();
    }
    return;
}

sub EVENT { ## no critic (ProhibitExcessComplexity)
    my ($self, $e, $err) = @_;
    my $m = $self->{_master};
    $e &= ~OUT;
    if (!$self->{_handshaked}) {
        $e &= ~SENT;
    }
    return if !$e && !$err;
    if ($e & IN) {
        $e &= ~IN;
        while (length $self->{in_buf}) {
            my ($error, $alertLevel, $alertDescription);
            my $rc = matrixSslDecode($self->{_ssl}, $self->{in_buf},
                my $buf=q{}, $error, $alertLevel, $alertDescription);
            if ($rc == $SSL_PROCESS_DATA) {
                $e |= IN;
                $m->{in_buf}    .= $buf;
                $m->{in_bytes}  += length $buf;
            }
            else {
                $self->{out_buf} .= $buf;
                $self->{_slave}->WRITE();
                ## no critic (ProhibitCascadingIfElse ProhibitDeepNests)
                if ($rc == $SSL_SUCCESS || $rc == $SSL_SEND_RESPONSE) {
                    if (!$self->{_handshaked}) {
                        if (matrixSslHandshakeIsComplete($self->{_ssl})) {
                            $self->{_handshaked} = 1;
                            undef $self->{_t};
                            if ($self->{_want_write}) {
                                $self->WRITE();
                            }
                        }
                    }
                }
                # WARNING   After $SSL_ERROR or $SSL_ALERT {in_buf} may
                # contain non-decoded packets. These packets will be lost,
                # except in case user will not $stream->close() on this
                # error AND there will be more data later (got EPOLLIN).
                # This behaviour is ok because all ERROR/ALERT are fatal
                # anyway (except NO_CERTIFICATE).
                # TODO FIXME    If we'll support commercial MatrixSSL we
                # should add handling for NO_CERTIFICATE case.
                elsif ($rc == $SSL_ERROR) {
                    $err ||= "ssl error: $SSL_alertDescription{$error}";
                    last;
                }
                elsif ($rc == $SSL_ALERT) {
                    if ($alertLevel == $SSL_ALERT_LEVEL_WARNING
                            && $alertDescription == $SSL_ALERT_CLOSE_NOTIFY) {
                        # Workaround MatrixSSL bug: ALERT packet doesn't removed
                        # from {in_buf}, and next matrixSslDecode() on this {in_buf}
                        # return SSL_ERROR while CLOSE_NOTIFY alert shouldn't be
                        # error at all. :(
                        # TODO Is it still needed in Crypt::MatrixSSL 1.83?
                        $self->{in_buf} = q{};
                    }
                    else {
                        $err ||= "ssl alert: $SSL_alertLevel{$alertLevel}: $SSL_alertDescription{$alertDescription}";
                        last;
                    }
                }
                elsif ($rc == $SSL_PARTIAL) {
                    last;
                }
                else {
                    $err ||= "matrixSslDecode: unexpected return code ($rc)";
                    last;
                }
                ## use critic
            }
        }
    }
    if ($e & RESOLVED) {
        $m->{ip} = $self->{ip};
    }
    if ($e & EOF) {
        $m->{is_eof} = $self->{is_eof};
        if (!$self->{_handshaked}) {
            $err ||= 'ssl handshake error: unexpected EOF';
        }
    }
    if ($e & CONNECTED) {
        $self->{_t} = EV::timer(TOHANDSHAKE, 0, $self->{_cb_t});
    }
    $m->EVENT($e, $err);
    return;
}


1; # Magic true value required at end of module
__END__

=encoding utf8

=for stopwords crt

=head1 NAME

IO::Stream::MatrixSSL - Crypt::MatrixSSL plugin for IO::Stream


=head1 VERSION

This document describes IO::Stream::MatrixSSL version v1.1.2


=head1 SYNOPSIS

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


=head1 DESCRIPTION

This module is plugin for IO::Stream which allow you to use SSL (on both
client and server streams).


=head1 INTERFACE 

=over

=item IO::Stream::MatrixSSL::Client->new(\%opt)

Create and return new IO::Stream plugin object.

There two optional parameters:

=over

=item cb

This should be CODE ref to your callback, which should check server
certificate. Callback will be called with two parameters: HASH ref with
certificate details, and ARRAY ref with two elements:
IO::Stream::MatrixSSL::Client object and IO::Stream object (see L<SYNOPSIS>
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

=item trusted_CA

This should be name of file (or files) with allowed CA certificates,
required to check RSA signature of server certificate. This module
installed with such file, so chances are you doesn't need to change
default {trusted_CA} value if you just wanna connect to https servers.

There may be many files listed in {trusted_CA}, separated by ";".
Each file can contain many CA certificates.

=back

=item IO::Stream::MatrixSSL::Server->new(\%opt)

Create and return new IO::Stream plugin object.

There at least two required parameters: {crt} and {key}. If {key} is
encrypted, then one more parameter required: {pass}.

=over

=item crt

This should be name of file (or files) with server certificate (or chain
of certificates). See above {trusted_CA} about format of this parameter.

=item key

This should be name of file with private key file for server certificate
(file should be in PEM format).

=item pass

If file with private key is encrypted, you should provide password for
decrypting it in this parameter.

=back

=back


=head1 DIAGNOSTICS

=head2 IO::Stream::MatrixSSL::Client

=over

=item C<< matrixSslReadKeys: wrong {trusted_CA}? >>

File with trusted CA certificates can't be read. If you provide own file,
there some problem with it. If you doesn't provided own file, then probably
this module was installed incorrectly - there should be default file with
trusted CA certificates (taken from Mozilla) installed with module.

=item C<< matrixSslNewSession: wrong {_ssl_session}? >>

This error shouldn't happens, it mean there some bug in this module,
or Crypt::MatrixSSL, or MatrixSSL itself.

=item C<< matrixSslEncodeClientHello >>

This error shouldn't happens, it mean there some bug in this module,
or Crypt::MatrixSSL, or MatrixSSL itself.

=back

=head2 IO::Stream::MatrixSSL::Server

=over

=item C<< {crt} and {key} required >>

You can't create SSL server without certificate and key files.

=item C<< matrixSslReadKeys: wrong {crt}, {key} or {pass}? >>

Certificate and key files you provided can't be read by MatrixSSL,
or may be you used wrong password for key file.

=item C<< matrixSslNewSession >>

This error shouldn't happens, it mean there some bug in this module,
or Crypt::MatrixSSL, or MatrixSSL itself.

=back


=head1 SUPPORT

=head2 Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at L<https://github.com/powerman/perl-IO-Stream-MatrixSSL/issues>.
You will be notified automatically of any progress on your issue.

=head2 Source Code

This is open source software. The code repository is available for
public review and contribution under the terms of the license.
Feel free to fork the repository and submit pull requests.

L<https://github.com/powerman/perl-IO-Stream-MatrixSSL>

    git clone https://github.com/powerman/perl-IO-Stream-MatrixSSL.git

=head2 Resources

=over

=item * MetaCPAN Search

L<https://metacpan.org/search?q=IO-Stream-MatrixSSL>

=item * CPAN Ratings

L<http://cpanratings.perl.org/dist/IO-Stream-MatrixSSL>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/IO-Stream-MatrixSSL>

=item * CPAN Testers Matrix

L<http://matrix.cpantesters.org/?dist=IO-Stream-MatrixSSL>

=item * CPANTS: A CPAN Testing Service (Kwalitee)

L<http://cpants.cpanauthors.org/dist/IO-Stream-MatrixSSL>

=back


=head1 AUTHOR

Alex Efros E<lt>powerman@cpan.orgE<gt>


=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2008-2016 by Alex Efros E<lt>powerman@cpan.orgE<gt>.

This is free software, licensed under:

  The GNU Public License

instead of less restrictive MIT only because…

MatrixSSL is distributed under the GNU Public License…

Crypt::MatrixSSL uses MatrixSSL, and so inherits the same license…

IO::Stream::MatrixSSL uses Crypt::MatrixSSL, and so inherits the same license.

GPL is a virus, avoid it whenever possible!


=cut
