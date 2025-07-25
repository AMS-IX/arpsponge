package M6::ArpSponge::Asctl::Arg::Log_Event_Mask;

use Moo;

extends 'Term::CLI::Argument';

use Term::CLI::Util qw( find_text_matches );
use M6::ArpSponge::Event qw( EVENT_NAMES parse_event_mask );

my @Events = EVENT_NAMES();

use namespace::clean;

around complete => sub {
    my ($orig, $self, $text, $state) = @_;

    my ($head, $partial) = $text =~ m{^(.*,)?(.*)};
    $head //= '';

    return map { $head.$_ } find_text_matches( $partial, \@Events );
};

sub translate {
    my ($self, $text, $state) = @_;

    #::DEBUG "translate: ", join(" ", map { "<$_>" } @_), "\n";

    my $err;
    my $mask = parse_event_mask(
        $text, -err => \$err );

    if (!defined $mask) {
        return $self->set_error($err);
    }

    return $mask;
}

sub validate {
    my ($self, $text, $state) = @_;

    #::DEBUG "validate: ", join(" ", map { "<$_>" } @_), "\n";

    my $mask = $self->translate($text, $state);
    return if !defined $mask;
    return $text;
}

1;
