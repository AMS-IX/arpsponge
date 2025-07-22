package M6::ArpSponge::Asctl::Arg::Arp_Update_Flags;

use Moo;

extends 'Term::CLI::Argument';

use Term::CLI::Util qw( find_text_matches );
use M6::ArpSponge::UpdateFlags qw( :const parse_update_flags );

my @Flags = sort ARP_UPDATE_FLAG_NAMES();

use namespace::clean;

around complete => sub {
    my ($orig, $self, $text, $state) = @_;

    my ($head, $partial) = $text =~ m{^(.*,)?(.*)};
    $head //= '';

    return map { $head.$_ } find_text_matches($partial, \@Flags);
};

sub translate {
    my ($self, $text, $state) = @_;

    my $err;
    my $flags = parse_update_flags(
        $text, -err => \$err );

    if (!defined $flags) {
        return $self->set_error($err);
    }

    return $flags;
}

sub validate {
    my ($self, $text, $state) = @_;

    my $flags = $self->translate($text, $state);
    return if !defined $flags;
    return $text;
}

1;
