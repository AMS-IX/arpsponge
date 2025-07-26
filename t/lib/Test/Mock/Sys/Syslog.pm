package Test::Mock::Sys::Syslog;

use 5.014;
use warnings;

use Moo;
use Test::MockModule;
use Sys::Syslog qw( :macros setlogmask );
use Carp qw( cluck carp );
use Time::Piece;
use FindBin;

use namespace::clean;

my %PRIO_NAME = (
    LOG_EMERG()   => 'EMERG',
    LOG_ALERT()   => 'ALERT',
    LOG_CRIT()    => 'CRIT',
    LOG_CRIT()    => 'CRIT',
    LOG_ERR()     => 'ERR',
    LOG_WARNING() => 'WARNING',
    LOG_NOTICE()  => 'NOTICE',
    LOG_INFO()    => 'INFO',
    LOG_DEBUG()   => 'DEBUG',
);

my %PRIO_LOOKUP = map {(
        $_ => $_,
        uc $PRIO_NAME{$_} => $_,
        lc $PRIO_NAME{$_} => $_,
)} keys %PRIO_NAME;

has _mockobj_list => (
    is => 'rw',
    default => sub { $_[0]->_build__mockobj_list },
);

has log_buffer  => (
    is      => 'lazy',
    clearer => 1,
    default => sub { [] },
);

has ident       => (is => 'rwp', init_arg => undef);
has logopt      => (is => 'rwp', init_arg => undef);
has facility    => (is => 'rwp', init_arg => undef);
has log_is_open => (is => 'rwp', init_arg => undef);

sub _prio_lookup {
    my $prio = lc $_[0];
    if (exists $PRIO_LOOKUP{$prio}) {
        $prio = $PRIO_LOOKUP{$prio};
        return ($prio, $PRIO_NAME{$prio});
    }
    cluck "unknown syslog priority '$prio'";
    return (LOG_EMERG, 'UNKNOWN');
}

sub _build__mockobj_list {
    my ($self) = @_;

    my @obj_list;

    my $caller;
    my $up = 1;
    while ($caller = caller($up)) {
        last if $caller ne __PACKAGE__;
        $up++;
    }
    if ($caller) {
        push @obj_list, $self->_build__mockobj($caller);
    }
    push @obj_list, $self->_build__mockobj('Sys::Syslog');
    return \@obj_list;
}

sub _build__mockobj {
    my ($self, $name) = @_;
    my $obj = Test::MockModule->new($name, no_auto => 1);

    my @mock;

    my %mock_map = (
        openlog    => sub { $self->_mock_openlog(@_) },
        closelog   => sub { $self->_mock_closelog(@_) },
        syslog     => sub { $self->_mock_syslog(@_) },
        setlogsock => sub { $self->_mock_setlogsock(@_) },
    );
    
    my @mock_list;

    for my $func (keys %mock_map) {
        my $sub = $name.'::'.$func;
        if (defined &{$sub}) {
            $obj->redefine( $func => $mock_map{$func} );
        }
    }
    return $obj;
}

sub _mock_setlogsock { return 1 }

sub _mock_openlog {
    my ($self, $ident, $logopt, $facility) = @_;

    if ($self->log_is_open) {
        cluck "openlog() called while log is already open!";
    }

    $ident    //= $FindBin::Script;
    $logopt   //= '';
    $facility //= LOG_USER;

    $self->_set_ident($ident);
    $self->_set_logopt($logopt);
    $self->_set_facility($facility);
    $self->_set_log_is_open(1);
    $self->clear_log_buffer();
    return;
}

sub _mock_closelog {
    my ($self) = @_;
    $self->_set_ident(undef);
    $self->_set_logopt(undef);
    $self->_set_facility(undef);
    $self->_set_log_is_open(0);
    $self->clear_log_buffer();
    return;
}

sub _mock_syslog {
    my ($self, $prio, $format, @args) = @_;

    if (!$self->log_is_open) {
        cluck "syslog() needs to call openlog()";
        $self->_mock_openlog();
    }

    my ($prio_num, $prio_name) = _prio_lookup($prio);
    my $mask = setlogmask(0);

    if (($mask & LOG_MASK($prio_num)) == 0) {
        return;
    }

    my $msg = @args ? sprintf($format, @args) : $format;
    chomp($msg);

    my $log_str = localtime->strftime("%FT%T%z mock-log ")
                . sprintf("%s[%d]: %s", $self->ident, $$, $msg);

    push @{$self->log_buffer}, [$prio_name, $log_str];
}

1;

__END__

=head1 NAME

Test::Mock::Sys::Syslog - mock out Sys::Syslog for unit tests

=head1 SYNOPSIS

    use Sys::Syslog qw( openlog closelog syslog :macros );
    use Test::Mock::Sys::Syslog;

    my $mock = Test::Mock::Sys::Syslog->new();

    openlog($LOG_IDENT, $LOG_OPT, $LOG_FACILITY);

    syslog($LOG_PRIO, $FMT, @ARGS);
    syslog($LOG_PRIO, $STR);

    setlogsock(...);

    closelog();

=head1 DESCRIPTION

The B<Test::Mock::Sys::Syslog> module provides a way to mock and test
L<B<Sys::Syslog>(3)|Sys::Syslog> interactions.

Usage is fairly straightforward:

=over

=item 1.

Import/require L<B<Sys::Syslog>(3)|Sys::Syslog>
adn B<Test::Mock::Sys::Syslog>.

    use Sys::Syslog qw( ... );
    use Test::Mock::Sys::Syslog;

=item 1.

Create an instance of a B<Test::Mock::Sys::Syslog> object:

    my $mock = Test::Mock::Sys::Syslog->new();

This will mock the functions in the
L<B<Sys::Syslog>(3)|Sys::Syslog> namespace,
as well as any of its functions that are imported into the
current namespace.

=item 2.

Use the L<B<Sys::Syslog>(3)|Sys::Syslog> interface.

=item 3.

Use the object's L<B<log_buffer>()|/log_buffer> to inspect the
generated log messages.

=item 4.

When the B<Test::Mock::Sys::Syslog> object goes out of scope, the
original interface is restored.

=back

=head1 CONSTRUCTOR

=head2 new

    OBJ = Test::Mock::Sys::Syslog->new();

Creates a new B<Test::Mock::Sys::Syslog>
object instance and returns a reference to it.

The object will mock relevant 
L<B<Sys::Syslog>(3)|Sys::Syslog>
functions,
see L<MOCKED FUNCTIONS/MOCKED FUNCTIONS>
below.

=head1 METHODS

=head2 clear_log_buffer

    OBJ->clear_log_buffer();

Clear the log buffer.

=head2 log_buffer

    ARRAY_REF = OBJ->log_buffer();

Return an array reference with log messages.
Each element is an array consisting of the priority (uppercase string)
and a message string.

Example:

  [
    [
      'INFO',
      '2025-07-26T23:20:09+0200 mock-log IDENT[PID]: MSG'
    ],
    [
      'DEBUG',
      '2025-07-26T23:20:09+0200 mock-log IDENT[PID]: MSG'
    ],
  ]

=head2 ident

The value of the I<$ident> parameter given to
L<B<openlog>()|Sys::Syslog/openlog>.

=head2 logopt

The value of the I<$logopt> parameter given to
L<B<openlog>()|Sys::Syslog/openlog>.

=head2 facility

The value of the I<$facility> parameter given to
L<B<openlog>()|Sys::Syslog/openlog>.

=head2 log_is_open

Boolean indicating if the log has been opened with
L<B<openlog>()|Sys::Syslog/openlog>
and not yet closed with
L<B<closelog>()|Sys::Syslog/closelog>.

=head1 MOCKED FUNCTIONS

=head2 openlog

    openlog($IDENT, $LOGOPT, $FACILITY);

Simulates the opening of a log connection.
After this call,
the L<B<log_is_open>()|/log_is_open> returns true.

=head2 closelog

    closelog();

Marks the log system as "closed".
After this call,
the L<B<log_is_open>()|/log_is_open> returns false.

=head2 syslog

    syslog($PRIORITY, $FMT, @ARGS);
    syslog($PRIORITY, $STR;

Simulates the original L<B<syslog>()|Sys::Syslog/syslog>.

Checks if I<$PRIORITY> (string or number) is included in
the log mask (see L<B<setlogmask>()|Sys::Syslog/setlogmask>.
If so, log message is created and added to the
L<B<log_buffer>()|/log_buffer>;
otherwise, this acts as a no-op.

=head2 setlogsock

Mocked to be a no-op.

=head1 EXAMPLE

The following code fragment shows how to use this module in a
L<B<Test2>(3)|Test2> environment:

    use 5.020;
    use warnings;

    use Test2::V0;

    use Sys::Syslog qw( openlog closelog syslog setlogsock :macros );
    use Test::Mock::Sys::Syslog;

    my $mock = Test::Mock::Sys::Syslog->new();

    openlog('tester', 'pid', 'user');
    syslog('info', "the time is %d", time);

    my $log_buffer = $mock->log_buffer;

    is scalar @${log_buffer}, 1, "log_buffer contains 1 entry";

    my ($log_prio, $log_msg) = @{$log_buffer->[0]};

    note("prio='$log_prio'; msg='$log_msg'");

    is $log_prio, 'INFO', "log message is an INFO message";

    like $log_msg, qr{ flubber\[\d+\]: the time is \d+$},
        "log message matches original syslog argument";

    closelog();

    done_testing();

=head1 SEE ALSO

L<B<Test2>(3)|Test2>,
L<B<Test2::V0>(3)|Test2::V0>,
L<B<Sys::Syslog>(3)|Sys::Syslog>.

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, 2025;
