#!/usr/bin/perl

use Modern::Perl;
use Scalar::Util qw( looks_like_number );

use lib qw( ../lib );
use M6::ARPSponge::State qw( :states );

say "States:";
for my $state ( M6::ARPSponge::State->ALL ) {
    printf("   %-10s %d\n", $state, $state);
}

print "\n";

my $state_1 = STATE_ALIVE;
my $state_2 = $state_1;

printf "state_1: %d (%s)\n", $state_1, $state_1;
printf "state_2: %d (%s)\n", $state_2, $state_2;

say "decrementing state_2:";

$state_2--;

say "state_2 is ", ($state_2 == STATE_DEAD)   ? "" : "not ", "DEAD";
say "state_2 is ", ($state_2 eq 'DEAD') ? "" : "not ", "DEAD";

my $state_3 = M6::ARPSponge::State->new_from_string('ALIVE');
printf "state_3: %d (%s)\n", $state_3, $state_3;

if (looks_like_number($state_3)) {
    print "$state_3 looks like a number.\n";
} else {
    print "$state_3 does not look like a number.\n";
}

my $undef = STATE_NONE;
my $str = $undef->to_string;
if (looks_like_number($undef)) {
    print "$undef looks like a number.\n";
} else {
    print "$undef does not look like a number.\n";
}

print "> ";
while (<>) {
    my $err = '?';
    my $state = M6::ARPSponge::State->new($_, -err => \$err);
    if (!defined $state) {
        say STDERR "ERROR: $err";
    }
    else {
        printf("%s = %d\n", $state, $state);
    }
    print "> ";
}
