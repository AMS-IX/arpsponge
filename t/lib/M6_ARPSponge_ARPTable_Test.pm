#===============================================================================
#       Module:  M6_ARPSponge_ARPTable_Test.pm
#
#  Description:  Test class for M6::ARPSponge::ARPTable
#
#       Author:  Steven Bakker (SB), <Steven.Bakker@ams-ix.net>
#
#   Copyright (c) 2015 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or modify
#   it under the same terms as Perl itself. See "perldoc perlartistic."
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6_ARPSponge_ARPTable_Test;

use parent qw( Test::Class );

use Modern::Perl;
use Test::More;

use M6::ARPSponge::ARPTable;
use M6::ARPSponge::NetPacket qw( :eth_addr );

sub startup : Test(startup => 2) {
    my $self = shift;

    use_ok( 'M6::ARPSponge::Util', ':all' );
    my $table = M6::ARPSponge::ARPTable->new();
    ok($table, 'M6::ARPSponge::ARPTable->new');

    $self->{'TABLE'}  = $table;
    $self->{'HEXIP1'}  = 'c1c28884';
    $self->{'HEXMAC1'} = 'a1b20304e5f6';
    $self->{'HEXIP2'}  = 'c1c28885';
    $self->{'HEXMAC2'} = 'a1b20304e5f7';
}

sub test_operations : Test(18) {
    my $self  = shift;
    my $table = $self->{'TABLE'};
    my $ip1   = $self->{'HEXIP1'};
    my $mac1  = $self->{'HEXMAC1'};
    my $ip2   = $self->{'HEXIP2'};
    my $mac2  = $self->{'HEXMAC2'};
    my $time  = time;

    my ($got_mac, $got_time);

    my $hash = $table->table;
    is(ref $hash, 'HASH', 'table ref');
    
    # Try an update with a timestamp.
    ok($table->update($ip1, $mac1, $time), 'update with time');
    ($got_mac, $got_time) = $table->lookup($ip1);
    ok(defined($got_mac) && defined($got_time), 'lookup');
    cmp_ok($got_mac, 'eq', $mac1, 'lookup, MAC address');
    cmp_ok($got_time, '==', $time, 'lookup, timestamp');

    # Try an update without a timestamp.
    ok($table->update($ip2, $mac2), 'update without time');
    ($got_mac, $got_time) = $table->lookup($ip2);
    ok(defined($got_mac) && defined($got_time), 'lookup');
    cmp_ok($got_mac, 'eq', $mac2, 'lookup, MAC address');
    cmp_ok($got_time, '>=', $time, 'lookup, timestamp');

    # Try an update with an ETH_ADDR_NONE (should delete the entry).
    ok($table->update($ip1, ETH_ADDR_NONE), 'update with ETH_ADDR_NONE');
    ($got_mac, $got_time) = $table->lookup($ip1);
    ok(!defined($got_mac), 'update with ETH_ADDR_NONE');

    # Try an update with an undef MAC (should delete the entry).
    ok($table->update($ip2, undef), 'update with undef');
    ($got_mac, $got_time) = $table->lookup($ip2);
    ok(!defined($got_mac), 'update with undef');

    # Add them back again...
    $table->update($ip1, $mac1, $time);
    $table->update($ip2, $mac2);

    # Now delete one again...
    ok($table->delete($ip1), 'delete existing entry');
    ($got_mac, $got_time) = $table->lookup($ip1);
    ok(!defined($got_mac), 'lookup deleted entry');

    # IP2 should still be there...
    ($got_mac, $got_time) = $table->lookup($ip2);
    ok(defined($got_mac) && defined($got_time), 'lookup');

    # Now clear the whole table...
    ok($table->clear, 'clear table');
    ($got_mac, $got_time) = $table->lookup($ip2);
    ok(!defined($got_mac), 'lookup cleared entry');
}

1;
