package Test::Mock::Net::Pcap;

use 5.014;
use warnings;

use Moo;
use Test::MockModule;
use Net::Pcap;
use Carp qw( cluck carp );
use Time::Piece;
use FindBin;
use Test::More;

use namespace::clean;

has _mockobj_list => ( is => 'rw' );

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
        pcap_close             => sub { $self->_pcap_close(@_) },
        pcap_setnonblock       => sub { $self->_pcap_setnonblock(@_) },
        pcap_get_selectable_fd => sub { $self->_pcap_get_selectable_fd(@_) },
        pcap_dispatch          => sub { $self->_pcap_dispatch(@_) },
        pcap_sendpacket        => sub { $self->_pcap_sendpacket(@_) },
        pcap_inject            => sub { $self->_pcap_inject(@_) },
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

sub _pcap_open_live {
    my ($self, @args) = @_;
    return 1;
}

sub _pcap_setnonblock {
    my ($self, @args) = @_;
    return 0;
}

sub _pcap_get_selectable_fd {
    my ($self, @args) = @_;
    return 0xff;
}

sub _pcap_dispatch {
    my ($self, @args) = @_;
    return 0;
}

sub _pcap_sendpacket {
    my ($self, $pcap_h, $packet) = @_;
    my $len = length($packet);
    note "MOCK pcap_sendpacket($pcap_h, [$len bytes])";
    return 0;
}

sub _pcap_inject {
    my ($self, @args) = @_;
    return 1;
}

sub _pcap_close {
    my ($self, @args) = @_;
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

=item 1.

Create an instance of a B<Test::Mock::Net::Pcap> object:

    my $mock = Test::Mock::Net::Pcap->new();

This will mock the functions in the
L<B<Net::Pcap>(3)|Net::Pcap> namespace,
as well as any of its functions that are imported into the
current namespace.

=item 2.

Use the L<B<Net::Pcap>(3)|Net::Pcap> interface.
Note that this module does not mock all functions of
L<B<Net::Pcap>(3)|Net::Pcap>.

=item 3.

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

=head1 MOCKED FUNCTIONS

=over

=item B<pcap_open_live>

=item B<pcap_close>

=item B<pcap_setnonblock>

=item B<pcap_get_selectable_fd>

=item B<pcap_dispatch>

=item B<pcap_sendpacket>

=item B<pcap_inject>

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
