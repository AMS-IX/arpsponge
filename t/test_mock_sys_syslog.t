#!perl

use 5.014;
use warnings;

use Test2::V0;
use FindBin;

use lib "$FindBin::Bin/lib";

use Sys::Syslog qw( :standard :macros );

use Test::Mock::Sys::Syslog;

my $mock = Test::Mock::Sys::Syslog->new();

openlog('flubber', 'pid', 'user');

TEST_DEFAULT: {
    syslog('info', "the time is %d", time);

    my $log_buffer = $mock->log_buffer;

    is scalar(@{$log_buffer}), 1, "log_buffer contains 1 entry";

    my ($log_prio, $log_msg) = @{$log_buffer->[0]};
    note("prio='$log_prio'; msg='$log_msg'");

    is $log_prio, 'INFO', "log message is an INFO message";

    like $log_msg, qr{ flubber\[\d+\]: the time is \d+$},
        "log message matches original syslog argument";

    $mock->clear_log_buffer();
}

TEST_ERR : {
    setlogmask(LOG_MASK(LOG_ERR));

    syslog('debug', "the time is %d", time);

    my $log_buffer = $mock->log_buffer;

    is scalar(@{$log_buffer}), 0, "mask=ERR; prio=DEBUG => log_buffer is empty";

    $mock->clear_log_buffer();
}

closelog();

done_testing();
