package Test::Mock::Net::Pcap;

use 5.014;
use warnings;

use Moo;
use Test::MockModule;
use Net::Pcap;
use Carp qw( confess );
use Time::Piece;
use Time::HiRes qw( gettimeofday );
use FindBin;
use Test::More;

use namespace::clean;

has _mockobj_list => ( is => 'rw' );
has _handles      => ( is => 'rw', default => sub { {} } );

has pkt_buffer  => (
    is       => 'lazy',
    clearer  => 1,
    init_arg => undef,
    default  => sub { [] },
);

sub BUILD {
    my ($self, $args) = @_;

    my @namespace;
    if (!exists $args->{namespace}) {
        @namespace = ( 'Net::Pcap' );

        my $caller;
        my $up = 1;

        while ($caller = caller($up)) {
            last if $caller ne __PACKAGE__;
            $up++;
        }
        if ($caller) {
            push @namespace, $caller;
        }
    }
    elsif (defined (my $namespace = $args->{namespace})) {
        if (!ref $namespace) {
            @namespace = ( $namespace );
        }
        else {
            @namespace = @{$namespace};
        }
    }

    my @list;
    for my $ns (@namespace) {
        push @list, $self->_build__mockobj($ns);
    }
    $self->_mockobj_list(\@list);
}

sub _build__mockobj {
    my ($self, $name) = @_;
    my $obj = Test::MockModule->new($name, no_auto => 1);

    my @mock;

    my %mock_map = (
        pcap_open_live         => sub { $self->_pcap_open_live(@_) },
        pcap_setnonblock       => sub { $self->_pcap_setnonblock(@_) },
        pcap_getnonblock       => sub { $self->_pcap_getnonblock(@_) },
        pcap_get_selectable_fd => sub { $self->_pcap_get_selectable_fd(@_) },
        pcap_dispatch          => sub { $self->_pcap_dispatch(@_) },
        pcap_sendpacket        => sub { $self->_pcap_sendpacket(@_) },
        pcap_inject            => sub { $self->_pcap_inject(@_) },
        pcap_close             => sub { $self->_pcap_close(@_) },
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

sub snaplen {
    my ($self, $pcap_h) = @_;

    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    return $self->_handles->{$pcap_h}->{snaplen};
}

sub get_sent {
    my ($self, $pcap_h) = @_;

    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    return $self->_handles->{$pcap_h}->{sent};
}

sub clear_sent {
    my ($self, $pcap_h) = @_;

    my $sent = $self->get_sent($pcap_h);
    @{$sent} = ();
    return;
}

sub add_sent {
    my ($self, $pcap_h, @pkts) = @_;

    my $queue = $self->get_sent($pcap_h);
    push @{$queue}, @pkts;
    return int(@pkts);
}


sub get_recv_queue {
    my ($self, $pcap_h) = @_;

    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    return $self->_handles->{$pcap_h}->{recv};
}

sub clear_recv_queue {
    my ($self, $pcap_h, @pkts) = @_;

    my $queue = $self->get_recv_queue($pcap_h);
    @{$queue} = ();
    return;
}

sub add_recv_queue {
    my ($self, $pcap_h, @pkts) = @_;

    my $queue = $self->get_recv_queue($pcap_h);
    push @{$queue}, @pkts;
    return int(@pkts);
}

sub fetch_recv_queue {
    my ($self, $pcap_h, @pkts) = @_;

    my $queue = $self->get_recv_queue($pcap_h);
    my $pkt = @{$queue} ? shift @{$queue} : undef;
    return $pkt;
}

sub _pcap_open_live {
    my ($self, $dev, $snaplen, $promisc, $to_ms, $err_r) = @_;

    my $pcap_h = pcap_open_dead(DLT_EN10MB, $snaplen);

    $self->_handles->{$pcap_h} = {
        dev      => $dev,
        snaplen  => $snaplen,
        promisc  => $promisc,
        to_ms    => $to_ms,
        nonblock => 0,
        recv     => [],
        sent     => [],
    };
    return $pcap_h;
}

sub _pcap_setnonblock {
    my ($self, $pcap_h, $mode, $err_r) = @_;

    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    $self->_handles->{$pcap_h}->{nonblock} = int($mode);
    return 0;
}

sub _pcap_getnonblock {
    my ($self, $pcap_h, $err_r) = @_;

    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    return int($self->_handles->{$pcap_h}->{nonblock});
}

sub _pcap_get_selectable_fd {
    my ($self, $pcap_h) = @_;
    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    return 0;
}

sub _pcap_dispatch {
    my ($self, $pcap_h, $count, $callback, $user) = @_;
    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }

    my $recv = $self->get_recv_queue($pcap_h);
    my $snaplen = $self->snaplen($pcap_h);

    $count = $count ? $count : @{$recv};

    my $processed = 0;
    while ($processed < $count && @{$recv}) {
        my $pkt = shift @{$recv};
        my ($tv_sec, $tv_usec) = gettimeofday();
        my $caplen = length($pkt);
        $caplen = $snaplen if $caplen > $snaplen;
        my %pkt_hdr = (
            tv_sec  => $tv_sec,
            tv_usec => $tv_usec,
            len     => length($pkt),
            caplen  => $caplen,
        );
        $callback->($user, \%pkt_hdr, substr($pkt, 0, $caplen));
        $processed++;

    }
    return $processed;
}

sub _pcap_sendpacket {
    my ($self, $pcap_h, $packet) = @_;
    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    my $len = length($packet);
    note "MOCK pcap_sendpacket($pcap_h, [$len bytes])";
    $self->add_sent($pcap_h, $packet);
    return 0;
}

sub _pcap_inject {
    my ($self, $pcap_h, $packet) = @_;
    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }
    my $len = length($packet);
    note "MOCK pcap_inject($pcap_h, [$len bytes])";
    $self->add_sent($pcap_h, $packet);
    return $len;
}

sub _pcap_close {
    my ($self, $pcap_h) = @_;
    if (!$self->_handles->{$pcap_h}) {
        confess 'p is not of type pcap_tPtr or has been closed';
    }

    pcap_close($pcap_h);
    delete $self->_handles->{$pcap_h};
    return;
}

1;

__END__

=head1 NAME

Test::Mock::Net::Pcap - mock out Net::Pcap for unit tests

=head1 SYNOPSIS

 use Net::Pcap;
 use Test::Mock::Net::Pcap;

 my $mock = Test::Mock::Net::Pcap->new();

 $pcap_h = pcap_open_live($dev, $snaplen, $promisc, $to_ms, \$err);

 $fd = pcap_get_selectable_fd($pcap_h);

 $count = pcap_dispatch($pcap_h, $count, \&callback, $user_data);

 pcap_setnonblock($pcap_h, $mode, \$err);

 $nonblock_mode = pcap_getnonblock($pcap_h);

 pcap_sendpacket($pcap_h, $packet);

 pcap_inject($pcap_h, $packet);

 pcap_close($pcap_h);

=head1 DESCRIPTION

The B<Test::Mock::Net::Pcap> module provides a way to mock and test
L<B<Net::Pcap>(3)|Net::Pcap> interactions.

Usage is fairly straightforward:

=over

=item 1.

Import/require
L<B<Net::Pcap>(3)|Net::Pcap>
and
B<Test::Mock::Net::Pcap>.

    use Net::Pcap;
    use Test::Mock::Net::Pcap;

=item 2.

Create an instance of a B<Test::Mock::Net::Pcap> object:

    my $mock = Test::Mock::Net::Pcap->new();

This will mock the functions in the
L<B<Net::Pcap>(3)|Net::Pcap> namespace,
as well as any of its functions that are imported into the
current namespace.

=item 3.

Use the L<B<Net::Pcap>(3)|Net::Pcap> interface.
Note that this module does not mock all functions of
L<B<Net::Pcap>(3)|Net::Pcap>.

=item 4.

When the B<Test::Mock::Net::Pcap> object goes out of scope, the
original interface is restored.

=back

B<NOTE:> The use of 
L<B<namespace::clean>(3)|namespace::clean>
may interfere with the use of this module,
see L<CAVEATS|/CAVEATS> below.

=head1 CONSTRUCTOR

=head2 new

    OBJ = Test::Mock::Net::Pcap->new();
    OBJ = Test::Mock::Net::Pcap->new( namespace => $NS);
    OBJ = Test::Mock::Net::Pcap->new( namespace => [ $NS, ... ] );

Creates a new B<Test::Mock::Net::Pcap>
object instance and returns a reference to it.

The object will mock relevant 
L<B<Net::Pcap>(3)|Net::Pcap>
functions,
see L<MOCKED FUNCTIONS/MOCKED FUNCTIONS>
below.

By default, it will mock C<pcap_> functions in the
C<Net::Pcap> and C<main> namespaces.

This allows you to write:

  use Net::Pcap;
  use Test::Mock::Net::Pcap;

  my $err;

  {
      my $mock = Test::Mock::Net::Pcap->new();

      # Mocked interface is now active.
      my $pcap_h = pcap_open_live('dummy', 1500, 1, 0, \$err);
  }

  # Original interface is now active.
  my $pcap_h = pcap_open_live('dummy', 1500, 1, 0, \$err);

If you want to override L<pcap_> functions in another module (namespace),
you can use the C<namespace> parameter to provide the namespace(s) for which
you want to override the interface, but see L<CAVEATS|/CAVEATS> below.

=head1 METHODS

The following methods can be used to manipulate incoming and outgoing
packets to the pcap interface.

=head2 get_sent

    $QUEUE_REF = $OBJ->get_sent($PCAP_H);

Return a reference to the list of packets that were sent on this
I<$PCAP_H> handle via C<pcap_sendpacket> or C<pcap_inject>.

The list contains a chronological record of binary packets.

=head2 add_sent

    $OBJ->add_sent($PCAP_H, $PACKET);

Add I<$PACKET> to the list of outgoing packets for I<$PCAP_H>.
This is called by the mocked C<pcap_sendpacket> and C<pcap_inject> functions.

=head2 clear_sent

    $OBJ->clear_sent($PCAP_H);

Clear the list of of outgoing packets for
I<$PCAP_H>.

=head2 get_recv_queue

    $QUEUE_REF = $OBJ->get_recv_queue($PCAP_H);

Return a reference to the list of incoming packets for
I<$PCAP_H> that can be consumed by C<pcap_dispatch>.

The list contains a chronological record of binary packets.

=head2 clear_recv_queue

    $OBJ->clear_recv_queue($PCAP_H);

Clear the list of of incoming packets for
I<$PCAP_H>.

=head2 add_recv_queue

    $OBJ->add_recv_queue($PCAP_H, $PACKET);

Add I<$PACKET> to the list of incoming packets for I<$PCAP_H>.

=head2 fetch_recv_queue

    $PACKET = $OBJ->fetch_recv_queue($PCAP_H);

Remove the next packet from the incoming queue for
I<$PCAP_H> and return it.
This is called by the mocked C<pcap_dispatch> function.

=head1 MOCKED FUNCTIONS

Mocked functions that require a pcap handle argument (I<$PCAP_H>)
will check its validity and throw an exception if the handle
was not created via this module (or if it has been closed since).

=over

=item B<pcap_open_live>

  $PCAP_H = pcap_open_live($DEV, $SNAPLEN, $PROMISC, $TO_MS, \$ERR);

Simulated by calling
L<B<pcap_open_dead>()|Net::Pcap/pcap_open_dead>,
so the return value is a valid pcap handle.

=item B<pcap_setnonblock>

  $RESULT = pcap_setnonblock($PCAP_H, $MODE, \$ERR);

Stores nonblock I<$MODE> for I<$PCAP_H>.
The mode is only stored, it is not interpreted in any way.
Always returns 0.

=item B<pcap_getnonblock>

  $MODE = pcap_getnonblock($PCAP_H, \$ERR);

Returns the stored nonblock mode for I<$PCAP_H>.

=item B<pcap_get_selectable_fd>

  $FT = pcap_get_selectable_fd($PCAP_H);

Always returns 0.

=item B<pcap_dispatch>

  $RECV_COUNT
    = pcap_dispatch($PCAP_H, $COUNT, \&CALLBACK, $USER_DATA);

Consumes packets from I<$PCAP_H>'s C<recv_queue> and
passes them to I<&CALLBACK>,
until I<$COUNT> packets have been consumed
or the end of the queue is reached.

Returns the number of packets processed.

=item B<pcap_sendpacket>

=item B<pcap_inject>

  $STATUS = pcap_sendpacket($PCAP_H, $PACKET);
  $SIZE   = pcap_inject($PCAP_H, $PACKET);

These functions add I<$PACKET> to the
C<sent> queue of I<$PCAP_H>.

=item B<pcap_close>

  pcap_close($PCAP_H);

Invalidates I<$PCAP_H> and clears all state for it.

=back

=head1 CAVEATS

=head2 Compatibility with "namespace::clean"

B<Test::Mock::Net::Pcap> cannot mock C<pcap_>
functions for a module that uses
L<B<namespace::clean>(3)|namespace::clean>,
I<unless>
B<Test::Mock::Net::Pcap>
is instantiated
I<before>
the target module is loaded.

Take, for instance, a fictitious module named C<Foo>:

  # Foo.pm
  package Reply;
  use Net::Pcap;
  use namespace::clean;

  sub send_reply {
      my ($msg) = @_;
      ...
      pcap_sendpacket($pcap_h, $packet);
  }

We then want to write test script that calls on C<Foo>,
with the 
L<B<Net::Pcap>(3)|Net::Pcap.3>
interface mocked out:

  # script.pl
  use Test::Mock::Net::Pcap;
  use Foo;

  my $mock = Test::Mock::Net::Pcap->new(namespace => 'Foo');

  Foo::send_reply('welcome');

Here, the constructor for
B<Test::Mock::Net::Pcap>
will try to install mock versions of L<pcap_> functions in
the C<Foo> namespace, but this will fail due to C<Foo>'s use of
C<namespace::clean>.

The solution is to instantiate 
B<Test::Mock::Net::Pcap>
I<before> the C<use Foo> statement:

  # script.pl
  use Test::Mock::Net::Pcap;
  my $mock_pcap;
  BEGIN {
      $mock_pcap = Test::Mock::Net::Pcap->new(namespace => 'Foo');
  }

  use Foo;

  Foo::send_reply('welcome');

The constructor can be called without a C<namespace> argument as well,
in which case it will mock the 
L<B<Net::Pcap>(3)|Net::Pcap.3>
interface for I<all> subsequent code/modules.

=head1 EXAMPLES

The following code fragment shows how to use this module in a
L<B<Test2>(3)|Test2> environment:

  use 5.020;
  use warnings;

  use Test2::V0;

  use Net::Pcap;
  use Test::Mock::Net::Pcap;

  my $mock = Test::Mock::Net::Pcap->new();

  my $err;
  my $pcap_h = pcap_open_live('lo', 1500, 0, 0, \$err);

  ...

  pcap_close($pcap_h);

  done_testing();

=head1 SEE ALSO

L<B<namespace::clean>(3)|namespace::clean>,
L<B<Net::Pcap>(3)|Net::Pcap>,
L<B<Test2>(3)|Test2>,
L<B<Test2::V0>(3)|Test2::V0>.

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, 2025;
