package Test::Mock::Net::Pcap;

use 5.014;
use warnings;

use Moo;
use Test::MockModule;
use Net::Pcap;
use Carp qw( cluck carp );
use Time::Piece;
use FindBin;

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
        else {
            $obj->mock( $func => $mock_map{$func} );
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
    my ($self, @args) = @_;
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

Import/require L<B<Net::Pcap>(3)|Net::Pcap>
adn B<Test::Mock::Net::Pcap>.

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

=head1 CONSTRUCTOR

=head2 new

    OBJ = Test::Mock::Net::Pcap->new();

Creates a new B<Test::Mock::Net::Pcap>
object instance and returns a reference to it.

The object will mock relevant 
L<B<Net::Pcap>(3)|Net::Pcap>
functions,
see L<MOCKED FUNCTIONS/MOCKED FUNCTIONS>
below.

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

=head1 EXAMPLE

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

L<B<Test2>(3)|Test2>,
L<B<Test2::V0>(3)|Test2::V0>,
L<B<Net::Pcap>(3)|Net::Pcap>.

=head1 AUTHOR

Steven Bakker E<lt>Steven.Bakker@ams-ix.netE<gt>, 2025;
