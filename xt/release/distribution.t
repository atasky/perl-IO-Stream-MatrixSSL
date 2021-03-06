use Test::More;

eval { require Test::Distribution };
plan( skip_all => 'Test::Distribution not installed' ) if $@;
Test::Distribution->import(
   podcoveropts => {
       also_private    => [
           qr/^(?:[A-Z_]+)$/,
       ],
       pod_from        => 'lib/IO/Stream/MatrixSSL.pm',
   }
);
