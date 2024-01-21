package M6::ArpSponge::Asctl::Arg_IP_Filter;

use Moo;

extends 'M6::ArpSponge::Asctl::Arg_IP_Range';

use Term::CLI::Util qw( is_prefix_str find_text_matches );

my @States = sort qw( all dead alive pending );

use namespace::clean;

around complete => sub {
    my ($orig, $self, $text, $state) = @_;

    if (!length $text) {
        return ($self->$orig($text, $state), @States);
    }
    return find_text_matches( $text, \@States );
};

around validate => sub {
    my ($orig, $self, $text, $state) = @_;

    #::DEBUG "validate: ", join(" ", map { "<$_>" } @_), "\n";

    my @state_matches = find_text_matches($text, \@States);

    return $state_matches[0] if @state_matches == 1;

    if (@state_matches > 1) {
        return $self->set_error(
            sprintf(qq{ambiguous value (matches: %s)},
                join(q{, }, @state_matches))
        );
    }
    return $self->$orig($text, $state);
};

1;
