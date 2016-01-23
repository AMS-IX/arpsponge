#!/usr/bin/perl

use Modern::Perl;
use lib qw( ../lib );
use Data::Dumper;

use FindBin;
use M6::CLI;

my $prog = $FindBin::Script;
my $term = M6::CLI->new(name => 'cli_demo', history_lines => 3);
$term->read_history();

my $syntax = $term->compile_syntax({
    'quit' => { '?' => 'Exit program.' },
    'help' => { '?' => 'Show command summary.' },
    'show status|performance|parameters|version|verbose|vitals' => {
        '?' => 'show stuff',
    },
    'ping $count? $delay? $fname?' => {
        '?'      => 'Send "ping" packets, display RTT.',
        '$count' => { type=>'int', min=>1, default=>1 },
        '$delay' => { type=>'float', min=>0.01, default=>1 },
        '$fname' => { type=>'filename', default=>'' },
    },
});

print Dumper($syntax);
my $FEAT = $term->term->Features;
print Dumper($FEAT);

say "history size: ", $term->history_lines;

my %args;
while (1) {
    my $input = $term->readline('~> ');
    last if !defined $input;

    next if $input =~ /^\s*(?:#.*)?$/;

    my @parsed;
    if ($term->parse_line($input, \@parsed, \%args)) {
        print "@parsed\n";
        print Dumper(\%args);
    }
}

$term->write_history();
