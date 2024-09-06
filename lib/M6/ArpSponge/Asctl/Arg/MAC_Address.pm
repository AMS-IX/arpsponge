package M6::ArpSponge::Asctl::Arg::MAC_Address;

use Moo;

extends 'Term::CLI::Argument::String';

use M6::ArpSponge::Util qw( mac2mac );

use namespace::clean;

sub validate {
    my ($self, $text, $state) = @_;

    #::DEBUG "validate: ", join(" ", map { "<$_>" } @_), "\n";

    if ($text =~ m{^ (?: [\da-f]{1,2} [:.-] ){5} [\da-f]{1,2}  $}xi
     || $text =~ m{^ (?: [\da-f]{1,4} [:.-] ){2} [\da-f]{1,4}  $}xi
     || $text =~ m{^                             [\da-f]{1,12} $}xi
    ) {
        return mac2mac($text);
    }

    return $self->set_error("invalid MAC address");
}

1;
