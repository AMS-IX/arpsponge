#perl

use 5.014;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";

use Test::More;
use Test::Trap qw( :default:stdout(tempfile):stderr(tempfile) );

use Test::Mock::Sys::Syslog;

my ($mock_syslog);

BEGIN {
    $mock_syslog = Test::Mock::Sys::Syslog->new();
}

use M6::ArpSponge::Log qw( :func );
use M6::ArpSponge::App::Settings;
use M6::ArpSponge::Defaults;
use M6::ArpSponge::State qw( :const );
use M6::ArpSponge::UpdateFlags qw( :const );
use M6::ArpSponge::NetPacket qw( :const :func );
use M6::ArpSponge::Util qw( :all );

# ($stdout, $stderr) = trap_output { code };
#
# More sure-fire way to trap output using temporary files.
#
sub trap_output(&) {
    my ($code) = @_;

    my $fh_out = File::Temp->new(
        TEMPLATE => 'arpsponge_test.XXXXXXXXXX',
        DIR => '/tmp',
    ) or BAIL_OUT("cannot create temp file in '/tmp': $!");

    open my $save_stdout, '>&', \*STDOUT
        or BAIL_OUT("cannot dup STDOUT: $!");

    open STDOUT, '>&', $fh_out
        or BAIL_OUT("cannot redirect STDOUT to '".$fh_out->filename."': $!");

    my $fh_err = File::Temp->new(
        TEMPLATE => 'arpsponge_test.XXXXXXXXXX',
        DIR => '/tmp',
    ) or BAIL_OUT("cannot create temp file in '/tmp': $!");

    open my $save_stderr, '>&', \*STDERR
        or BAIL_OUT("cannot dup STDERR: $!");

    open STDERR, '>&', $fh_err
        or BAIL_OUT("cannot redirect STDERR to '".$fh_err->filename."': $!");

    trap { $code->() };

    open STDERR, '>&', $save_stderr
        or BAIL_OUT("cannot restore STDERR: $!");
    open STDOUT, '>&', $save_stdout
        or BAIL_OUT("cannot restore STDOUT: $!");

    $fh_out->seek(0,0);
    my $stdout = do { local($/) = undef; <$fh_out> };
    close $fh_out;

    $fh_err->seek(0,0);
    my $stderr = do { local($/) = undef; <$fh_err> };
    close $fh_err;

    return ($stdout, $stderr);
}


my $dev_arg     = 'eth0';
my $net_arg     = '198.51.100.0/24';

my $net_addr    = NetAddr::IP->new($net_arg);
my $prefixlen   = $net_addr->masklen;
my $network_s   = $net_addr->addr;
my $broadcast_s = $net_addr->broadcast->addr;
my $network_h   = ip2hex($network_s);
my $broadcast_h = ip2hex($broadcast_s);

subtest 'Minimal CLI arguments' => sub {
    my @argv = (
        "--network=$net_arg",
        "--device=$dev_arg",
    );

    my $settings;

    $settings = M6::ArpSponge::App::Settings->new(args => [@argv]);
    isa_ok($settings, 'M6::ArpSponge::App::Settings');
    is $settings->error, '', 'new() with options works';

    $settings = M6::ArpSponge::App::Settings->new(
        args => [$net_addr->cidr, 'dev', $dev_arg]
    );
    is $settings->error, '', 'new() with arguments works';

    $settings = M6::ArpSponge::App::Settings->new();
    isa_ok($settings, 'M6::ArpSponge::App::Settings');

    $settings->parse_command_line(args => [$argv[0]]);
    like $settings->error, qr{not enough (arguments|parameters)},
        "parse_command_line() detects missing 'device'";

    $settings->parse_command_line(args => [$net_addr->cidr, $dev_arg]);
    like $settings->error, qr{not enough (arguments|parameters)},
        "parse_command_line() catches missing 'dev' argument";

    $settings->parse_command_line(args => [$net_addr->cidr, 'thing', $dev_arg]);
    like $settings->error, qr{expected 'dev'},
        "parse_command_line() catches mismatched 'dev' argument";

    $settings->parse_command_line(
        args => [$net_addr->cidr, 'dev', $dev_arg, 'more']
    );
    like $settings->error, qr{too many (arguments|parameters)},
        "parse_command_line() catches too many arguments";

    $settings->parse_command_line(args => [$argv[1]]);
    like $settings->error, qr{not enough (arguments|parameters)},
        "parse_command_line() detects missing 'network'";

    $settings->parse_command_line();
    like $settings->error, qr{not enough (arguments|parameters)},
        "parse_command_line() without parameters works";

};


subtest 'All CLI options' => sub {
    my @argv1 = (
        '--max-arp-age=1234',
        '--arp-update-flags=none',
        '--control-socket=/tmp/sponge/control',
        '--daemon-mode',
        '--device='.$dev_arg,
        '--dummy-mode',
        '--passive-mode',
        '--static-mode',
        '--flood-protection=1.2',
        '--gratuitous',
        '--init-state=DEAD',
        '--learn-time=567',
        '--log-level=debug',
        '--log-mask=state,io',
        '--network='.$net_arg,
        '--max-pending=42',
        '--socket-permissions=bin:bin:0644',
        '--pid-file=/tmp/sponge/pid',
        '--probe-rate=10',
        '--queue-depth=234',
        '--max-arp-rate=45',
        '--run-dir=/tmp/sponge',
        '--sponge-network',
        '--status-file=/tmp/sponge/status',
        '--sweep=300/3600',
        '--sweep-at-start',
        '--sweep-skip-alive',
        '--verbose',
    );
    my $settings = M6::ArpSponge::App::Settings->new(args => [@argv1]);
    isa_ok($settings, 'M6::ArpSponge::App::Settings');
    is $settings->error, '', 'new() with ALL options works';

    my @argv2 = (
        '--age=1234',
        '--arp-update-methods=none',
        '--no-daemon-mode',
        '--device='.$dev_arg,
        '--no-dummy-mode',
        '--no-passive-mode',
        '--no-static-mode',
        '--no-gratuitous',
        '--learning=567',
        '--loglevel=warning',
        '--logmask=all,!ctl',
        '--network='.$net_arg,
        '--pending=84',
        '--permissions=daemon:daemon:0660',
        '--pidfile=/tmp/sponge/pid',
        '--proberate=3.4',
        '--queuedepth=567',
        '--rate=67',
        '--rundir=/tmp/sponge',
        '--statusfile=/tmp/sponge/status',
        '--no-sweep-at-start',
        '--no-sweep-skip-alive',
    );
    $settings->parse_command_line(args => [@argv2]);
    is $settings->error, '', 'alternative/negated options work';
};


subtest 'Automatic settings' => sub {
    my @base_arg = (
        '--device='.$dev_arg,
        '--network='.$net_arg,
    );
    my $settings = M6::ArpSponge::App::Settings->new();

    $settings->parse_command_line(args => [@base_arg]);
    my $run_dir        = $settings->hash->{'run_dir'};
    my $control_socket = $settings->hash->{'control_socket'};
    my $pid_file       = $settings->hash->{'pid_file'};
    my $status_file    = $settings->hash->{'status_file'};

    is $status_file, "$run_dir/status",
        "'status_file' is set relative to default 'run_dir'";
    is $pid_file, "$run_dir/pid",
        "'pid_file' is set relative to default 'run_dir'";
    is $control_socket, "$run_dir/control",
        "'control_socket' is set relative to default 'run_dir'";

    $run_dir = '/FOO';

    $settings->parse_command_line(args => [@base_arg, "--run-dir=$run_dir"]);

    $control_socket = $settings->hash->{'control_socket'};
    $pid_file       = $settings->hash->{'pid_file'};
    $status_file    = $settings->hash->{'status_file'};

    is $settings->hash->{'run_dir'}, $run_dir,
        "'--run-dir=$run_dir' sets 'run_dir' to '$run_dir'";
    is $status_file, "$run_dir/status",
        "'status_file' is set relative to '$run_dir'";
    is $pid_file, "$run_dir/pid",
        "'pid_file' is set relative to '$run_dir'";
    is $control_socket, "$run_dir/control",
        "'control_socket' is set relative to '$run_dir'";
};


subtest 'Bad CLI options' => sub {
    my @base_opts = (
        '--device='.$dev_arg,
        '--network='.$net_arg,
    );

    my @bad_opts = (
        [ '--network'           , 'nope'    , 'invalid'          ],

        [ '--max-arp-age'       , 'nope'    , 'non-numerical'    ],
        [ '--max-arp-age'       , -1        , 'negative'         ],

        [ '--arp-update-flags'  , 'nope'    , 'invalid'          ],
        [ '--flood-protection'  , 'nope'    , 'non-numerical'    ],
        [ '--flood-protection'  , 0         , 'non-positive'     ],
        [ '--init-state'        , 'NOPE'    , 'invalid'          ],

        [ '--learn-time'        , 'nope'    , 'non-numerical'    ],
        [ '--learn-time'        , -1        , 'negative'         ],

        [ '--log-level'         , 'nope'    , 'invalid'          ],
        [ '--log-mask'          , 'nope'    , 'invalid'          ],

        [ '--max-pending'       , 'nope'    , 'non-numerical'    ],
        [ '--max-pending'       , 0         , 'non-positive'     ],

        [ '--socket-permissions', ''           , 'empty'         ],
        [ '--socket-permissions', 'root:root'  , 'incomplete'    ],
        [ '--socket-permissions', '*:root:0644', 'invalid owner' ],
        [ '--socket-permissions', 'root:*:0644', 'invalid group' ],
        [ '--socket-permissions', 'root:root:*', 'invalid mode'  ],

        [ '--probe-rate'        , 'nope'    , 'non-numerical'    ],
        [ '--probe-rate'        , 0         , 'non-positive'     ],

        [ '--queue-depth'       , 'nope'    , 'non-numerical'    ],
        [ '--queue-depth'       , 0         , 'non-positive'     ],

        [ '--max-arp-rate'      , 'nope'    , 'non-numerical'    ],
        [ '--max-arp-rate'      , -1        , 'negative'         ],

        [ '--sweep'             , 'nope'    , 'invalid'          ],
    );

    for my $opt (@bad_opts) {
        my ($name, $val, $reason) = @{$opt};
        my @opts = (
            @base_opts,
            "$name=$val",
        );
        my $settings = M6::ArpSponge::App::Settings->new(args => \@opts);
        my $opt_name = $name =~ s{^-+}{}r;
        like $settings->error, qr{\b$opt_name\b},
            "$reason value for '$name' is caught";
    }
};


subtest 'Help, manual, version' => sub {
    my $settings = M6::ArpSponge::App::Settings->new();

    like(
        $settings->usage_msg(),
        qr{try .* --help}i,
        "usage message mentions '--help'"
    );

    trap { $settings->parse_command_line(args => ['--help']) };
    is $trap->exit, 0, "'--help' exits with code 0";
    like $trap->stdout, qr{usage.*options}is,
        "'--help' prints usage information";

    my ($stdout, $stderr) = trap_output {
        $settings->parse_command_line(args => ['--man'])
    };
    is $trap->exit, 0, "'--man' exits with code 0";

    $stdout =~ s{\e\[\d*m}{}gs; # strip ANSII "SGR" sequences.
    like $stdout, qr{\bname\b .* \bsynopsis\b .* \bdescription\b}isx,
        "'--man' prints manual page";

    trap { $settings->parse_command_line(args => ['--version']) };
    is $trap->exit, 0, "'--version' exits with code 0";

    like $trap->stdout, qr{^\S+ \h+ \d[\w.\-]+$}x,
        "'--version' prints version information";
};

done_testing;
