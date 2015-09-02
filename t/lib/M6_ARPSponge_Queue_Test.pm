#===============================================================================
#       Module:  M6_ARPSponge_Queue_Test.pm
#
#  Description:  Test class for M6::ARPSponge::Queue
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

package M6_ARPSponge_Queue_Test;

use parent qw( Test::Class );

use Modern::Perl;
use Test::More;

use M6::ARPSponge::Queue qw(:all);

sub startup : Test(startup => 2) {
    my $self = shift;
    use_ok( 'M6::ARPSponge::Queue' );
    my $queue = M6::ARPSponge::Queue->new( max_depth => 5);
    ok(defined $queue, 'constructor');
    $self->{'queue'} = $queue;
}


sub test_methods : Test(1) {
    my $q = shift->{'queue'};
    my @methods = qw(
        max_depth
        clear_all
        clear
        depth
        rate
        is_full
        add
        get_entry
        get_timestamp
        get_queue
        reduce
    );
    can_ok( $q, @methods);
}

1;
