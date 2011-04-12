#!@PERL@ -I../lib
# ============================================================================
# @(#)$Id$
# ============================================================================
#
#         File:  aslogtail.pl
#
#        Usage:  see POD at end
#
#  Description:  ArpSponge Log Tail
#
#       Author:  Steven Bakker (SB), <steven.bakker@ams-ix.net>
#      Created:  2011-03-24 15:38:13 CET
#
#   Copyright (c) 2011 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# ============================================================================

$0 =~ s|.*/||g;

use feature ':5.10';
use strict;
use warnings;
use Getopt::Long qw( GetOptions );
use Pod::Usage;
use M6::ARP::Control::Client;
use M6::ARP::Util qw( :all );

my $SPONGE_VAR    = '@SPONGE_VAR@';
my $CONN          = undef;

# Values set on the Command Line.
my $opt_verbose   = undef;
my $rundir        = $SPONGE_VAR;
my $HISTFILE      = "$::ENV{HOME}/.$0_history";

($::VERSION) = '$Revision: 1.0$' =~ /Revision: (\S+)\$/;
my $app_header = "\nThis is $0, v$::VERSION\n\n"
               . "See \"perldoc $0\" for more information.\n"
               ;

sub verbose(@) { print @_ if $opt_verbose; }

sub Main {
    my ($sockname, $raw) = initialise();

    verbose "connecting to arpsponge on $sockname\n";
    my $conn = M6::ARP::Control::Client->create_client($sockname)
                or die M6::ARP::Control::Client->error."\n";

    while ( my @lines = $conn->read_log_data(-blocking => 1) ) {
        if ($raw) {
            print @lines;
        }
        else {
            for my $log (@lines) {
                $log =~ s/^(\S+)\t(\d+)\t/format_time($1,' ')." [$2] "/e;
                print $log;
            }
        }
    }
    $conn->close;
    exit(0);
}

sub initialise {
    GetOptions(
        'verbose'     => \$opt_verbose,
        'help|?'      =>
            sub { pod2usage(-msg => $app_header, -exitval=>0, -verbose=>0) },
        'interface=s' => \(my $interface),
        'rundir=s'    => \$rundir,
        'socket=s'    => \(my $sockname),
        'raw'         => \(my $raw = 0),
        'manual'      => sub { pod2usage(-exitval=>0, -verbose=>2) },
    ) or pod2usage(-exitval=>2);

    if ($sockname) {
        if ($interface) {
            die "$0: --socket and --interface are mutually exclusive\n";
        }
    }
    elsif ($interface) {
        $sockname = "$rundir/$interface/control";
    }
    else {
        for my $entry (glob("$rundir/*")) {
            if (-S "$entry/control") {
                $sockname = "$entry/control";
                last;
            }
        }
        if (!$sockname) {
            die "$0: cannot find sponge instance in $rundir\n";
        }

    }
    
    if (@ARGV) {
        pod2usage(-msg => "Too many arguments", -exitval=>2);
    }

    return ($sockname, $raw);
}

##############################################################################

Main();

__END__

=head1 NAME

xxx - do xxx

=head1 SYNOPSIS

 xxx [--verbose|--quiet] infile

=head1 DESCRIPTION

=head1 OPTIONS

=over

=item X<--verbose>X<--quiet>B<--verbose> | B<--quiet>

By default, only a short summary of the progress is printed to STDOUT.
The C<--verbose> flag causes the program to be a little more talkative,
the C<--quiet> flag suppresses all non-error output to STDOUT.

=back

=head1 EXAMPLES

=head1 SEE ALSO

L<perl(1)|perl>.

=head1 AUTHOR

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2011.

=cut

