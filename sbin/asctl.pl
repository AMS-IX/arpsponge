#!@PERL@ -I../lib
# ============================================================================
# @(#)$Id$
# ============================================================================
#
#         File:  asctl.pl
#
#        Usage:  see POD at end
#
#  Description:  ArpSponge ConTroL utility.
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
use Getopt::Long;
use Pod::Usage;
use M6::ARP::Control;
use Term::ReadLine;

my $SPONGE_VAR    = '@SPONGE_VAR@';
my $OUT           = \*STDOUT;
my $IN            = \*STDIN;

# Values set on the Command Line.
my $opt_verbose   = 0;
my $opt_debug     = 0;
my $rundir        = $SPONGE_VAR;

($::VERSION) = '$Revision: 1.0$' =~ /Revision: (\S+)\$/;
my $app_header = "\nThis is $0, v$::VERSION\n\n"
               . "See \"perldoc $0\" for more information.\n"
               ;

sub verbose(@) { print @_ if $opt_verbose; }

sub Main {
    my ($sockname, $args) = initialise();
    
    my ($term, $prompt);
    if (!@$args) {
        $term   = new Term::ReadLine 'asctl';
        $OUT    = $term->OUT || \*STDOUT;
        $IN     = $term->IN  || \*STDIN;
        select $OUT;
        $| = 1;

        $prompt = (-t $IN && -t $OUT) ? "asctl> " : '';

        $opt_verbose //= 1 if -t $OUT;
    }

    verbose "connecting to arpsponge on $sockname\n";
    my $conn = M6::ARP::Control::Client->new($sockname)
                or die M6::ARP::Control->error;

    my $err = 0;

    if (@$args) {
        my $command = do_command($conn, join(' ', @$args));
    }
    else {
        while ( defined (my $input = $term->readline($prompt)) ) {
            next if $input =~ /^\s*(?:#.*)?$/;
            $term->addhistory($input);
            my $command = do_command($conn, $input);

            if (!defined $conn->send_command("ping")) {
                if ($command eq 'quit') {
                    verbose "connection closed\n";
                }
                else {
                    $err++;
                    print STDERR "** connection closed unexpectedly\n";
                }
                last;
            }
        }
    }
    $conn->close;
    exit $err;
}

sub do_command {
    my $conn  = shift;
    my $input = shift;
    my ($command, @args) = split(' ', $input);
    $command = lc $command;
    $input = join(' ', $command, @args);

    given ($command) {
        when ('show') {
        }
        when ('set') {
        }
        when ('clear') {
        }
        when ('sponge') {
        }
        when ('sponge') {
        }
    }

    if ($input =~ /^\s*show\s+log\s*$/) {
        if (my $log = $conn->get_log_buffer(-order => -1)) {
            print_output($log);
        }
    }
    elsif ($input =~ /^\s*clear\s+log\s*$/) {
        $conn->clear_log_buffer;
    }
    else {
        my $reply = $conn->send_command($input);
        if (!defined $reply) {
            print STDERR "ERROR: ", $conn->error, "\n";
        }
        else {
            print_output($reply);
        }
    }
    return $command;
}

sub initialise {
    my ($sockname, $interface);
    GetOptions(
        'verbose'     => \$opt_verbose,
        'help|?'      =>
            sub { pod2usage(-msg => $app_header, -exitval=>0, -verbose=>0) },
        'interface=s' => \$interface,
        'rundir=s'    => \$rundir,
        'socket=s'    => \$sockname,
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

    return ($sockname, [@ARGV]);
}

sub print_output {
    my $out = join('', @_);
       $out =~ s/\n+\[OK\]\s*\Z//s;

    if (-t $OUT) {
        open(MORE, "|less"
                   ." --no-lessopen --no-init --dumb"
                   ." --quit-at-eof --quit-if-one-screen");
        print MORE $out;
        close MORE;
    }
    else {
        print $out;
    }
}

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

