 use Modern::Perl;
 use lib qw( .. );
 use Data::Dumper;

 use FindBin;
 use M6::CLI qw( :all );

 my $prog = $FindBin::Script;
 init_readline(
            'history_lines' => 1000,
            'completion'    => \&M6::CLI::complete_line,
            'name'          => $prog,
            'history_file'  => "$::ENV{HOME}/.${prog}_history",
        );

 my $syntax = compile_syntax({
    'quit' => { '?' => 'Exit program.' },
    'help' => { '?' => 'Show command summary.' },
    'ping $count? $delay?' => {
        '?'      => 'Send "ping" packets, display RTT.',
        '$count' => { type=>'int', min=>1, default=>1 },
        '$delay' => { type=>'float', min=>0.01, default=>1 },
    }
 });

 print Dumper($syntax);

 my @parsed;
 my %args;
 while (1) {
    my $input = $TERM->readline('~> ');
    last if !defined $input;

    next if $input =~ /^\s*(?:#.*)?$/;

    if (parse_line($input, \@parsed, \%args)) {
        print "@parsed\n";
        print Dumper(\%args);
    }
    else {
        print "ERROR\n";
    }
 }

 exit_readline();
