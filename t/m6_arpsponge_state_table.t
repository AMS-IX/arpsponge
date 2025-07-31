#perl -T

use 5.014;
use warnings;

use Test::More;

use M6::ArpSponge::StateTable;
use M6::ArpSponge::State qw( :const );
use M6::ArpSponge::Util qw( ip2hex hex2ip hex2mac );
use Scalar::Util qw( reftype );
use Time::HiRes qw( time );

my $table = M6::ArpSponge::StateTable->new();

my $all_state_info = $table->get_all_state_info();
my $all_pending    = $table->get_all_pending();

is scalar keys %{$all_state_info}, 0,
    "fresh state table has no state entries";

is scalar keys %{$all_pending}, 0,
    "fresh state table has no pending entries";

my $ip = '203.0.113.1';

subtest 'empty table' => sub {
    ok !$table->has_state(ip2hex($ip)),
        "has_state('$ip') returns false for a fresh table";

    ok !defined $table->get_state_info(ip2hex($ip)),
        "get_state_info('$ip') returns undef for a fresh table";

    ok !defined $table->get_state(ip2hex($ip)),
        "get_state('$ip') returns undef for a fresh table";

    ok !defined $table->get_mtime(ip2hex($ip)),
        "get_mtime('$ip') returns undef for a fresh table";

    ok !defined $table->get_atime(ip2hex($ip)),
        "get_atime('$ip') returns undef for a fresh table";

    ok !defined $table->is_pending(ip2hex($ip)),
        "is_pending('$ip') returns undef for a fresh table";
};

subtest 'pending IP' => sub {
    $table->set_state(ip2hex($ip), PENDING(0));

    ok $table->has_state(ip2hex($ip)),
        "has_state('$ip') returns true";

    my $state_info = $table->get_state_info(ip2hex($ip));

    is reftype($state_info), 'HASH',
        "get_state_info('$ip') returns state (HASH ref)";

    is $state_info->{state}, PENDING(0),
        "get_state_info('$ip')->{state} is PENDING(0)";

    cmp_ok $state_info->{mtime}, '>', 0,
        "get_state_info('$ip')->{mtime} > 0";

    cmp_ok $state_info->{atime}, '>', 0,
        "get_state_info('$ip')->{atime} > 0";

    is $table->get_state(ip2hex($ip)), PENDING(0),
        "get_state('$ip') returns PENDING(0)";

    cmp_ok $table->get_mtime(ip2hex($ip)), '>', 0,
        "get_mtime('$ip') returns > 0";

    cmp_ok $table->get_atime(ip2hex($ip)), '>', 0,
        "get_atime('$ip') returns > 0";

    is reftype($state_info), 'HASH',
        "get_state_info('$ip') returns state (HASH ref) for a fresh table";

    ok $table->is_pending(ip2hex($ip)),
        "is_pending('$ip') returns true";

    my $all_pending = $table->get_all_pending();
    is scalar keys %{$all_pending}, 1,
        "get_all_pending() returns one entry";
};

subtest 'clear_all' => sub {
    $table->clear_all();

    my $all_state_info = $table->get_all_state_info();
    my $all_pending    = $table->get_all_pending();

    is scalar keys %{$all_state_info}, 0,
        "cleared table has no state entries";

    is scalar keys %{$all_pending}, 0,
        "cleared table has no pending entries";
};

subtest 'state tests' => sub {
    my $time = Time::Piece->strptime("1985-12-01T02:00:00+0100", "%FT%T%z");
    my $epoch = $time->epoch;
    
    my @state = (
        [ 'ALIVE'      => ALIVE ],
        [ 'PENDING(3)' => PENDING(3) ],
        [ 'DEAD'       => DEAD ],
    );

    for my $elt (@state) {
        my ($state_name, $state) = @{$elt};

        note "set_state('$ip', $state_name, $epoch)";
        $table->set_state(ip2hex($ip), $state, $epoch);

        is $table->get_state(ip2hex($ip)), $state,
        "get_state('$ip') returns $state_name";

        is $table->get_mtime(ip2hex($ip)), $epoch,
            "get_mtime('$ip') returns $epoch";

        is $table->get_atime(ip2hex($ip)), $epoch,
            "get_atime('$ip') returns $epoch";

        if ($state < PENDING(0)) {
            ok !$table->is_pending(ip2hex($ip)),
                "is_pending('$ip') returns false";
        }
        else {
            ok $table->is_pending(ip2hex($ip)),
                "is_pending('$ip') returns true";
        }
        $epoch += 10;
    }

    my %no_state = (
        'NONE' => NONE,
        'undef' => undef,
    );

    for my $k (sort keys %no_state) {
        note "set_state('$ip', ALIVE, $epoch)";
        $table->set_state(ip2hex($ip), ALIVE, $epoch);

        note "set_state('$ip', $k, $epoch)";
        $table->set_state(ip2hex($ip), $no_state{$k}, $epoch);

        ok !$table->has_state(ip2hex($ip)),
            "has_state('$ip') returns false";

        ok !defined $table->get_state_info(ip2hex($ip)),
            "get_state_info('$ip') returns undef";

        ok !defined $table->get_state(ip2hex($ip)),
                "get_state('$ip') returns undef";

        ok !defined $table->get_mtime(ip2hex($ip)),
            "get_mtime('$ip') returns undef";

        ok !defined $table->get_atime(ip2hex($ip)),
            "get_atime('$ip') returns undef";

        ok !defined $table->is_pending(ip2hex($ip)),
            "is_pending('$ip') returns undef";
    }
};

subtest 'time tests' => sub {
    my $time = Time::Piece->strptime("1985-12-01T02:00:00+0100", "%FT%T%z");
    my $epoch = $time->epoch;

    note "set_state('$ip', ALIVE, $epoch)";
    $table->set_state(ip2hex($ip), ALIVE, $epoch);

    is $table->get_mtime(ip2hex($ip)), $epoch,
        "get_mtime('$ip') returns $epoch";

    is $table->get_atime(ip2hex($ip)), $epoch,
        "get_atime('$ip') returns $epoch";

    my $mtime = $epoch + 60;
    my $atime = $epoch + 120;

    note "set_atime('$ip', $atime)";
    $table->set_atime(ip2hex($ip), $atime);
    note "set_mtime('$ip', $mtime)";
    $table->set_mtime(ip2hex($ip), $mtime);

    is $table->get_atime(ip2hex($ip)), $atime,
        "get_atime('$ip') returns $atime";
    is $table->get_mtime(ip2hex($ip)), $mtime,
        "get_mtime('$ip') returns $mtime";

    my ($t0, $t1);
    $t0 = time;
        $table->set_atime(ip2hex($ip));
    $t1 = time;
    $atime = $table->get_atime(ip2hex($ip));

    ok $t0 <= $atime && $atime <= $t1,
        "set_atime('$ip') sets atime to current time"
    or diag "atime == $atime; expected $t0..$t1";

    $t0 = time;
        $table->set_mtime(ip2hex($ip));
    $t1 = time;
    $mtime = $table->get_mtime(ip2hex($ip));

    ok $t0 <= $mtime && $mtime <= $t1,
        "set_mtime('$ip') sets mtime to current time"
    or diag "mtime == $mtime; expected $t0..$t1";
};

done_testing();
