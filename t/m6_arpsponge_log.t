#!perl
#
# Unit tests for M6::ArpSponge::Log

use 5.014;
use warnings;

#use Test2::V0;
use Test::More;
use Test::Output;
use Test::Exception;

use FindBin;

use lib "$FindBin::Bin/lib";

use M6::ArpSponge::Log qw(:func :macros);

use Test::Mock::Sys::Syslog;

my $mock = Test::Mock::Sys::Syslog->new(namespace => 'M6::ArpSponge::Log');

subtest 'init_log' => sub {
    ok init_log(), "init_log() returns true";
    is LOG_IDENT, $FindBin::Script, "init_log() sets LOG_IDENT to \$FindBin::Script";

    ok init_log('test'), "init_log('test') returns true";
    is LOG_IDENT, 'test', "init_log('test') sets LOG_IDENT to 'test'";

    ok $mock->log_is_open, "init_log() calls openlog()";

    cmp_ok log_buffer_size(), '>', 0,
        "log_buffer_size() is greater than 0";

};

subtest 'is_valid_log_level' => sub {
    my @prio = (LOG_MIN_LEVEL .. LOG_MAX_LEVEL);
    for my $want_prio (@prio) {
        my $prio_name = log_level_to_string($want_prio);
        my $got_prio = is_valid_log_level($prio_name);
        is $got_prio, $want_prio,
            "is_valid_log_level('$prio_name') returns $want_prio";

        $got_prio = is_valid_log_level(uc $prio_name);
        is $got_prio, $want_prio,
            "is_valid_log_level('\U$prio_name\E') returns $want_prio";
    }
    my $err = undef;
    my $prio_name = 'OOPSIE';
    my $got_prio = is_valid_log_level($prio_name, err => \$err);
    is $got_prio, undef, "is_valid-log_level('$prio_name') returns undef";
};

subtest 'log_level_to_string' => sub {
    my $prio = LOG_MIN_LEVEL;
    my $want_prio = log_level_to_string($prio);
    my $prio_name = log_level_to_string($prio-1);

    is $prio_name, $want_prio,
        "log_level_to_string(LOG_MIN_LEVEL-1) returns $want_prio";

    $prio = LOG_MAX_LEVEL;
    $want_prio = log_level_to_string($prio);
    $prio_name = log_level_to_string($prio+1);

    is $prio_name, $want_prio,
        "log_level_to_string(LOG_MAX_LEVEL+1) returns $want_prio";
};


subtest 'log_level(LOG_DEBUG)' => sub {
    log_level(LOG_DEBUG);

    # All these messages should be logged...
    log_emerg(   '[1] emerg message'   );
    log_alert(   '[2] alert message'   );
    log_crit(    '[3] crit message'    );
    log_err(     '[4] err message'     );
    log_warning( '[5] warning message' );
    log_notice(  '[6] notice message'  );
    log_info(    '[7] info message'    );
    log_debug(   '[8] debug message'   );

    my $buf = get_log_buffer();
    is int(@{$buf}), 8, "LOG_DEBUG logs 8 messages in internal buffer";

    $buf = $mock->log_buffer();
    is int(@{$buf}), 8, "LOG_DEBUG logs 8 syslog messages";

    my @prio = (LOG_MIN_LEVEL .. LOG_MAX_LEVEL);
    while (my ($i, $prio) = each @prio) {
        my $want_prio = log_level_to_string($prio);
        my ($got_prio, $got_msg) = @{$buf->[$i]};
        is $got_prio, uc $want_prio,
            "[LOG_DEBUG] syslog entry no. $i is '\U$want_prio\E'";

        my $n = $i+1;
        like $got_msg, qr{\[$n\] $want_prio message},
            "[LOG_DEBUG] syslog message no. $i is correct";
    }
};

subtest 'log_level(LOG_WARNING)' => sub {
    $mock->clear_log_buffer();
    clear_log_buffer();

    log_level(LOG_WARNING);

    # All these messages should be logged...
    log_emerg(   '[1] emerg message'   );
    log_alert(   '[2] alert message'   );
    log_crit(    '[3] crit message'    );
    log_err(     '[4] err message'     );
    log_warning( '[5] warning message' );

    # These messages should not be logged...
    log_notice(  '[6] notice message'  );
    log_info(    '[7] info message'    );
    log_debug(   '[8] debug message'   );


    my $n_expected = 5;

    my $buf = get_log_buffer();
    is int(@{$buf}), $n_expected,
        "LOG_WARNING logs $n_expected messages in internal buffer";

    $buf = $mock->log_buffer();
    is int(@{$buf}), $n_expected,
        "LOG_WARNING logs $n_expected syslog messages";

    my @prio = (LOG_MIN_LEVEL .. LOG_WARNING);
    while (my ($i, $prio) = each @prio) {
        my $want_prio = log_level_to_string($prio);
        my ($got_prio, $got_msg) = @{$buf->[$i]};
        is $got_prio, uc $want_prio,
            "[LOG_WARNING] syslog entry no. $i is '\U$want_prio\E'";

        my $n = $i+1;
        like $got_msg, qr{\[$n\] $want_prio message},
            "[LOG_WARNING] syslog message no. $i is correct";
    }
};

package TestNotify {
    use parent qw( File::Temp );

    sub new {
        my ($class) = @_;
        my $self = File::Temp->new( DIR => '/tmp', TEMPLATE => '.notifyXXXXXXXXX' );
        return bless $self, $class;
    }

    sub send_log {
        my ($self, @msg) = @_;
        $self->print(@msg);
    }
}

subtest 'notify' => sub {
    $mock->clear_log_buffer();
    clear_log_buffer();

    log_level(LOG_INFO);

    my $notify_fh = TestNotify->new();
    add_notify($notify_fh);

    $notify_fh->print("an info message");
    log_info('an info message');

    $notify_fh->seek(0,0);
    my $notify_output = <$notify_fh>;
    like $notify_output, qr{an info message},
        "log_info() prints to notify handle";

    remove_notify($notify_fh);
    close $notify_fh;
};

subtest 'print_log' => sub {
    $mock->clear_log_buffer();
    clear_log_buffer();

    log_level(LOG_NOTICE);

    print_log('a message');

    my $n_expected = 1;

    my $buf = get_log_buffer();
    is int(@{$buf}), $n_expected,
        "print_log() adds a message to the internal buffer";

    $buf = $mock->log_buffer();
    is int(@{$buf}), $n_expected,
        "print_log() logs a syslog messages";
};

subtest 'log_is_verbose' => sub {
    log_is_verbose(0);
    $mock->clear_log_buffer();
    clear_log_buffer();

    log_level(LOG_NOTICE);

    my ($msg, $fmt, @args);

    $msg = "a verbose message";
    stdout_is( sub { log_verbose(1, $msg) }, '',
        "log_verbose(1, ...) prints nothing if verbosity is 0.");

    $fmt = "a message from %s[%d]";
    @args = ($FindBin::Script, $$);
    stdout_is(
        sub { log_sverbose(1, $fmt, @args) }, '',
        "log_sverbose(1, ...) prints nothing if verbosity is 0.");

    log_is_verbose(1);

    $msg = "another verbose message";
    stdout_like( sub { log_verbose(1, $msg) }, qr{\Q$msg\E},
        "log_verbose(1, ...) prints message if verbosity is 1.");

    $fmt = "another message from %s[%d]";
    @args = ($FindBin::Script, $$);
    $msg = sprintf($fmt, @args);
    stdout_like(
        sub { log_sverbose(1, $fmt, @args) },
        qr{\Q$msg\E},
        "log_sverbose(1, ...) prints message if verbosity is 1.");

    $msg = "a log message";
    stdout_like(
        sub { print_log($msg) },
        qr{\Q$msg\E},
        "print_log() prints message to STDOUT if verbosity is 1.");

    my $buf = get_log_buffer();
    is int(@{$buf}), 1,
        "print_log() adds a message to the internal buffer if verbosity is 1.";

    $buf = $mock->log_buffer();
    is int(@{$buf}), 0,
        "print_log() logs no syslog messages if verbosity is 1.";

};

subtest 'log_buffer_size' => sub {
    $mock->clear_log_buffer();
    log_is_verbose(0);
    clear_log_buffer();
    my $bufsiz = 4;
    log_buffer_size($bufsiz);

    for my $i (1..$bufsiz) {
        print_log("message %d", $i);
    }

    my $buf = get_log_buffer();
    is int(@{$buf}), $bufsiz,
        "log buffer holds $bufsiz lines after $bufsiz messages";

    my ($got_tstamp, $got_msg);

    ($got_tstamp, $got_msg) = @{$buf->[0]};
    like $got_msg, qr{message 1},
            "first message matches 'message 1'";
    ($got_tstamp, $got_msg) = @{$buf->[-1]};
    like $got_msg, qr{message $bufsiz},
            "last message matches 'message $bufsiz'";

    my $new_n = $bufsiz + 1;
    print_log("message $new_n");

    is int(@{$buf}), $bufsiz,
        "log buffer holds $bufsiz lines after ${new_n} messages";

    ($got_tstamp, $got_msg) = @{$buf->[0]};
    unlike $got_msg, qr{message 1},
            "oldest message ('message 1') has been removed";

    ($got_tstamp, $got_msg) = @{$buf->[-1]};
    like $got_msg, qr{message $new_n},
            "last message now matches 'message $new_n'";

    my $old_size = int(@{$buf});
    $bufsiz--;
    log_buffer_size($bufsiz);
    my $new_size = int(@{$buf});

    is $new_size, $bufsiz,
        "log buffer reduced to $bufsiz lines after log_buffer_size($bufsiz)";
};

subtest 'log_fatal' => sub {
    throws_ok { log_fatal('a FATAL message') } qr{a FATAL message},
        "log_fatal(\$msg) dies with appropriate message";

    my $buf = $mock->log_buffer();
    my ($prio, $msg) = @{$buf->[-1]};
    like $msg, qr{a FATAL message},
        "log_fatal() logs appropriate message";

    my $crit = uc log_level_to_string(LOG_CRIT);
    is $prio, $crit,
        "log_fatal() logs message at '$crit' level";

    throws_ok { log_fatal('a FATAL message from %d', $$) }
        qr{a FATAL message from $$},
        "log_fatal(\$fmt, \@args) dies with appropriate message";

};
done_testing();
