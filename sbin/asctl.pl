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
use Getopt::Long qw( GetOptions GetOptionsFromArray );
use Pod::Usage;
use M6::ARP::Control::Client;
use M6::ARP::Util qw( :all );
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
    my $conn = M6::ARP::Control::Client->create_client($sockname)
                or die M6::ARP::Control::Client->error."\n";

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

sub check_send_command {
    my $conn = shift;
    my $command = join(' ', @_);

    my $reply = $conn->send_command($command) or return;
       $reply =~ s/^\[(\S+)\]\s*\Z//m;

    if ($1 eq 'OK') {
        return $reply;
    }
    else {
        return print_error($reply);
    }
}

sub dispatch {
    my $conn    = shift;
    my $parsed  = shift;
    my $args    = shift;
    my $valid   = shift;

    my $prefix = join('', map { $_.'_' } @$parsed);
    my %commands = map { $_ => eval '\&do_'.$prefix.$_ } @$valid;

    my $command = lc shift @$args;
    push @$parsed, $command;
    if (exists $commands{lc $command}) {
        my $func = $commands{lc $command};
        if (defined &$func) {
            return $func->($conn, $parsed, $args);
        }
        else {
            print_error("[INTERNAL] @$parsed: not implemented!");
        }
    }
    else {
        print_error("@$parsed: command unknown");
    }
    return 0;
}

sub do_command {
    my $conn  = shift;
    my @args = split(' ', shift);

    dispatch($conn,
                    [],
                    [ @args ],
                    [ qw( quit status show set clear sponge unsponge ) ]
           );

    return $args[0];
}

sub check_arg_count {
    my ($min, $max, $command, $args) = @_;

    $min //= int(@$args);
    $max //= int(@$args);

    return 1 if @$args >= $min && @$args <= $max;

    my $arguments = $max==1 ? "argument" : "arguments";
    if ($min == $max) {
        if (!$min) {
            return print_error(qq{"$command" takes no arguments});
        }
        return print_error(qq{"$command" needs $min $arguments});
    }
    if ($min+1 == $max) {
        return print_error(qq{"$command" needs $min or $max $arguments});
    }
    if (@$args < $min) {
        my $arguments = $min==1 ? "argument" : "arguments";
        return print_error(qq{"$command" needs at least $min $arguments});
    }
    if ($min) {
        return print_error("$command: specify $min-$max $arguments");
    }
    return print_error("$command: specify up to $max $arguments");
}

sub do_quit {
    my ($conn, $parsed, $args) = @_;
    my $reply = check_send_command($conn, 'quit') or return;
    print_output($reply);
}

sub do_show {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;
    my $command = join(' ', @$parsed);

    check_arg_count(1,undef,$command, $args) or return;

    return dispatch($conn,
                    $parsed,
                    $args,
                    [ qw( status log arp version uptime ip ) ]
           );
}

sub do_clear {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;
    my $command = join(' ', @$parsed);

    check_arg_count(1,undef,$command, $args) or return;

    return dispatch($conn,
                    $parsed,
                    $args,
                    [ qw( ip arp log ) ]
           );
}

sub do_show_log {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    GetOptionsFromArray($args,
                'raw!'    => \(my $raw = 0),
                'format!' => \$format,
                'nf'      => sub { $format = 0 },
            ) or return;

    $format &&= !$raw;

    check_arg_count(0,0,"@$parsed", $args) or return;

    my $log = $conn->get_log_buffer(-order => -1) or return;
    if ($format) {
        $log =~ s/^(\d+)\t(\d+)\t/format_time($1,' ')." [$2] "/gme;
    }
    print_output($log);
}

sub do_clear_log {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    check_arg_count(0,0,"@$parsed", $args) or return;

    my $log = $conn->get_log_buffer(-order => -1);
    $conn->clear_log_buffer;
    print_output(length($log)." bytes cleared");
}

sub do_show_status {
    return do_status(@_);
}

sub do_status {
    my ($conn, $parsed, $args) = @_;
    my $format = 1;

    GetOptionsFromArray($args,
                'raw!'    => \(my $raw = 0),
                'format!' => \$format,
                'nf'      => sub { $format = 0 },
            ) or return;

    $format &&= !$raw;

    check_arg_count(0,0,"@$parsed", $args) or return;
    
    my $reply = check_send_command($conn, 'get_status') or return;

    if (!$raw) {
        $reply =~ s/^(network|ip)=([\da-f]+)$/"$1=".hex2ip($2)/gme;
        $reply =~ s/^(mac)=([\da-f]+)$/"$1=".hex2mac($2)/gme;
    }
    if (!$format) {
        print_output($reply);
    }
    else {
        my %info = map { split(/=/, $_) } split("\n", $reply);
        my $taglen = 0;
        foreach (keys %info) {
            $taglen = length($_) if length($_) > $taglen;
        }
        $taglen++;
        my $tag = "%-${taglen}s ";
        print_output(
            sprintf("$tag%s\n", 'id:', $info{id}),
            sprintf("$tag%s\n", 'version:', $info{version}),
            sprintf("$tag%s [%d]\n", 'date:',
                    format_time($info{date}), $info{date}),
            sprintf("$tag%s [%d]\n", 'started:',
                    format_time($info{started}), $info{started}),
            sprintf("$tag%s/%d\n", 'network:',
                    $info{network}, $info{prefixlen}),
            sprintf("$tag%s\n", 'interface:', $info{interface}),
            sprintf("$tag%s\n", 'IP:', $info{ip}),
            sprintf("$tag%s\n", 'MAC:', $info{mac}),
            sprintf("$tag%d\n", 'queue depth:', $info{queue_depth}),
            sprintf("$tag%0.2f\n", 'max rate:', $info{max_rate}),
            sprintf("$tag%0.2f\n", 'flood protection:',
                    $info{flood_protection}),
            sprintf("$tag%0.2f\n", 'max pending:', $info{max_pending}),
            sprintf("$tag%d\n", 'sweep period:', $info{sweep_period}),
            sprintf("$tag%d\n", 'sweep age:', $info{sweep_age}),
            sprintf("$tag%d\n", 'proberate:', $info{proberate}),
            sprintf("$tag%s (in %d secs) [%d]\n", 'next sweep:',
                    format_time($info{next_sweep}),
                    $info{next_sweep}-$info{date},
                    $info{next_sweep}),
            sprintf("$tag%s\n", 'learning', $info{learning}?'yes':'no'),
            sprintf("$tag%s\n", 'dummy', $info{dummy}?'yes':'no'),
        );
    }
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

sub print_error {
    my $out = join('', @_);
       $out .= "\n" if $out !~ /\n\Z/;
    print STDERR $out;
    return;
}

sub print_output {
    my $out = join('', @_);
       $out .= "\n" if $out !~ /\n\Z/;

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

