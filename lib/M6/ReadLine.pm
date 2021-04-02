#===============================================================================
#
#       Module:  M6::ReadLine
#         File:  ReadLine.pm
#
#  Description:  parse/validate/completion for programs that use ReadLine.
#
#        Files:  Parser.pm
#       Author:  Steven Bakker (SB), <steven.bakker@ams-ix.net>
#      Created:  2011-04-21 13:28:04 CEST
#
#   Copyright 2011-2016 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc
#   perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#   See the "Copying" file that came with this package.
#
#===============================================================================

package M6::ReadLine;

use strict;
use warnings;
use feature ':5.10';
use base qw( Exporter );
use Term::ReadLine;
use Term::ReadKey;
use NetAddr::IP;
use M6::ARP::Util qw( :all );
use Data::Dumper;
use M6::ARP::Sponge qw( :flags );
use Scalar::Util qw( reftype );

BEGIN {
    use Exporter;

    our $VERSION     = '1.00';
    my  @check_func  = qw(
            check_ip_address_arg  complete_ip_address_arg
            check_int_arg
            check_float_arg
            check_bool_arg
            match_prefix
        );
    my  @gen_functions = qw( compile_syntax init_readline exit_readline
                             parse_line
                             print_error_cond print_error
                             last_error set_error clear_error
                             yesno print_output
                             clr_to_eol term_width fmt_text );
    my  @functions   = (@check_func, @gen_functions);
    my  @vars        = qw( $TERM $IN $OUT $PROMPT $PAGER
                           $HISTORY_FILE $IP_NETWORK );
    our @EXPORT_OK   = (@functions, @vars);
    our @EXPORT      = @gen_functions;
    our %EXPORT_TAGS = ( func => \@functions, check => \@check_func,
                         all => \@EXPORT_OK, vars => \@vars );
}

our $TERM         = undef;
our $IN           = \*STDIN;
our $OUT          = \*STDOUT;
our $PROMPT       = '';
our $HISTORY_FILE = '';
our $IP_NETWORK   = NetAddr::IP->new('0/0');
our $SYNTAX       = {};
our $PAGER        = join(' ', qw(
                        less --no-lessopen --no-init
                             --dumb  --quit-at-eof
                             --quit-if-one-screen
                    ));

my $CLR_TO_EOL    = undef;
my $ERROR         = undef;

our %TYPES = (
        'int' => {
            'verify'   => \&check_int_arg,
            'complete' => [],
        },
        'float' => {
            'verify'   => \&check_float_arg,
            'complete' => [],
        },
        'bool' => {
            'verify'   => \&check_bool_arg,
            'complete' => [ qw( true false on off yes no ) ],
        },
        'mac-address' => {
            'verify'   => \&check_mac_address_arg,
            'complete' => [],
        },
        'ip-address' => {
            'verify'   => \&check_ip_address_arg,
            'complete' => \&complete_ip_address_arg,
        },
        'string' => {
            'verify'   => sub { return clear_error($_[1]) },
            'complete' => []
        },
        'filename' => {
            'verify'   => sub { return clear_error($_[1]) },
            'complete' => \&complete_filename,
        },
    );

# $word = match_prefix($input, \@words [, $silent]);
sub match_prefix {
    my ($input, $words, $silent) = @_;

    my $word;
    for my $w (sort @$words) {
        if (substr(lc $w, 0, length($input)) eq lc $input) {
            if (defined $word) {
                return print_error_cond(!$silent,
                        qq{"$input" is ambiguous: matches "$word" and "$w"}
                    );
            }
            $word = $w;
        }
    }
    return clear_error($word);
}

# $byte = check_int_arg(\%spec, $arg, 'byte');
sub check_int_arg {
    my ($spec, $arg, $silent) = @_;
    my $min     = $spec->{min};
    my $max     = $spec->{max};
    my $argname = $spec->{name} // 'num';

    my $err;
    my $val = is_valid_int($arg, -min=>$min, -max=>$max, -err=>\$err);
    if (defined $val) {
        return clear_error($val);
    }
    return print_error_cond(!$silent, qq{$argname: "$arg": $err});
}

# $percentage = check_float_arg({min=>0, max=>100}, $arg, 'percentage');
sub check_float_arg {
    my ($spec, $arg, $silent) = @_;
    my $min     = $spec->{min};
    my $max     = $spec->{max};
    my $argname = $spec->{name} // 'num';

    my $err;
    my $val = is_valid_float($arg, -min=>$min, -max=>$max, -err=>\$err);
    if (defined $val) {
        return clear_error($val);
    }
    return print_error_cond(!$silent, qq{$argname: "$arg": $err});
}

# $bool = check_bool_arg($min, $max, $arg, 'dummy');
sub check_bool_arg {
    my ($spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'bool';

    my $err;

    my $val = is_valid_bool($arg, -err => \$err);
    if (defined $val) {
        return clear_error($val);
    }

    return print_error_cond(!$silent, qq{$argname: "$arg": $err});
}

sub check_ip_address_arg {
    my ($spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'ip';

    my $err;
    $arg = is_valid_ip($arg, -network=>$IP_NETWORK->cidr, -err=>\$err);
    if (defined $arg) {
        return clear_error($arg);
    }
    return print_error_cond(!$silent, qq{$argname: $err});
}

sub check_mac_address_arg {
    my ($spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'mac';

    if ($arg =~ /^(?:[\da-f]{1,2}[:.-]){5}[\da-f]{1,2}$/i
        || $arg =~ /^(?:[\da-f]{1,4}[:.-]){2}[\da-f]{1,4}$/i
        || $arg =~ /^[\da-f]{1,12}$/i) {
        return clear_error($arg);
    }
    print_error_cond($silent, qq{$argname: "$arg" is not a valid MAC address});
    return;
}

sub complete_ip_address_arg {
    my $partial = shift;

    my $network   = $IP_NETWORK->short;

    my $fixed_octets = int($IP_NETWORK->masklen / 8);

    return $network if $fixed_octets == 4;
    return undef    if $fixed_octets == 0;

    my $fixed = join('.', (split(/\./, $network))[0..$fixed_octets-1] );
    my $have_len = length($partial);
    if ($have_len > 0 && $have_len > length($fixed)) {
        my @completions = (map { "$fixed.$_" } (0..255));
        if ($have_len >= $fixed_octets) {
            # Turn IP addresses into "91.200.17.1[x[x[x]]]"
            # That is, keep the part that has already matched
            # and reveal only the next digit, turn the rest into "x".
            my %completions = map {
                    my $keep = substr($_, 0, $have_len+1);
                    my $hide = length($_) > $have_len+1
                                ? substr($_, $have_len+1)
                                : '';
                    $hide =~ s/[\da-f]/x/gi;
                    $keep.$hide => 1;
                } @completions;
            return keys %completions;
            #return grep { length($_) <= $have_len+1 } @completions;
        }
        return grep { length($_) == length($fixed)+2 } @completions;
    }
    return ("$fixed.", "$fixed.x");
}

sub complete_filename {
    my $partial = shift;
    my $attribs = $TERM->Attribs;
    my @list;
    my $state = 0;
    while (my $f = $attribs->{filename_completion_function}->($partial, $state)) {
        push @list, $f;
        $state = 1;
    }
    return @list;
}

# $ok = parse_line($line, \@parsed, \%args);
#
#   Parse the input line in $line against $SYNTAX (compiled syntax). All
#   parsed, literal command words (i.e. neither argument nor option) are
#   stored in @parsed. All arguments and options are stored in %args.
#
#   Returns 1 on success, undef on failure.
#
sub parse_line {
    my ($line, $parsed, $args) = @_;
    chomp($line);
    my @words = split(' ', $line);
    $args->{'-options'} = [];
    return parse_words(\@words, { words => $SYNTAX }, $parsed, $args);
}

# $ok = parse_words(\@words, $syntax, \@parsed, \%args);
#
#   Parse the words in @words against $syntax (compiled syntax). All
#   parsed, literal command words (i.e. neither argument nor option) are
#   stored in @parsed. All arguments and options are stored in %args.
#
#   Returns 1 on success, undef on failure.
#
sub parse_words {
    my $words      = shift;
    my $syntax     = shift;
    my $parsed     = shift;
    my $args       = shift;

    # Command line options (--something, -s), are stored
    # in the '-options' array in %$args. They'll be parsed
    # later on.
    while (@$words && $$words[0] =~ /^-{1,2}./) {
        push @{$args->{-options}}, shift @$words;
    }

    if (my $word_list = $syntax->{words}) {
        my $words_str = join(q{ }, sort grep { length $_ } keys %$word_list);

        if (!@$words) {
            return 1 if exists $word_list->{''};
            return print_error("@$parsed: expected one of:\n",
                                fmt_text('', $words_str, undef, 4));
        }
        my $w = $words->[0];
        my $l = length($w);
        my @match = grep { substr($_,0, $l) eq $w } keys %$word_list;
        if (@match == 1) {
            push @$parsed, $match[0];
            shift @$words;
            return parse_words(
                    $words, $word_list->{$match[0]},
                    $parsed, $args
            );
        }
        if (@match > 1) {
            return print_error(
                qq{ambibuous input "$$words[0]"; matches:\n},
                fmt_text('', join(" ", sort @match), undef, 4),
            );
        }
        return print_error(
            qq{invalid input "$$words[0]"; expected one of:\n},
            fmt_text('', $words_str, undef, 4)
        );
    }

    if (my $arg_spec = $syntax->{arg}) {
        my $arg_name = $arg_spec->{name};
        $args->{$arg_name} = $arg_spec->{default};
        if (!@$words) {
            if ($arg_spec->{optional}) {
                return parse_words($words, $arg_spec, $parsed, $args);
            }
            return print_error("@$parsed: missing <$arg_name> argument");
        }
        my $arg_val;
        if (my $type = $TYPES{$arg_spec->{type}}) {
            my $validate = $type->{verify} // sub { $_[0] };
            eval { $arg_val = $validate->($arg_spec, $words->[0]) };
        }
        else {
            $arg_val = $words->[0];
        }
        return if ! defined $arg_val;
        $args->{$arg_name} = $arg_val;
        shift @$words;
        return parse_words($words, $arg_spec, $parsed, $args);
    }

    if (@$words) {
        return print_error(
            qq{@$parsed: expected end of line instead of "$$words[0]"\n}
        );
    }

    return 1;
}

# @completions = complete_words(\@words, $partial, \%syntax);
#
#   @words   - Words leading up to $partial.
#   $partial - Word to complete.
#   %syntax  - Syntax definition tree.
#
# Recursively traverse the %syntax try by looking up consecutive values of
# @words. At the end, either the current element's "words" entry will give
# the list of completions, or the "completion" function of the "var" entry.
#
sub complete_words {
    my $words      = shift;
    my $partial    = shift;
    my $syntax     = shift;

    if (my $word_list = $syntax->{words}) {
        my @next = sort grep { length $_ } keys %$word_list;
        my @literals = @next;
        if (exists $word_list->{''}) {
            push @literals, '';
            push @next, '(return)';
        }
        if (!@$words) {
            return (\@literals, \@next);
        }
        my $w = $words->[0];
        my $l = length($w);
        my @match = grep { substr($_,0, $l) eq $w } keys %$word_list;
        if (@match == 1) {
            shift @$words;
            return complete_words($words, $partial, $word_list->{$match[0]});
        }

        if (@match > 1) {
            return ([],
                [qq{** "$$words[0]" ambiguous; matches: }
                . join(', ', sort @match)]
            );
        }

        return([],
            [qq{** "$$words[0]" invalid; expected: }
            . join(", ", sort @next)]
        );
    }

    if (my $arg_spec = $syntax->{arg}) {
        my $arg_name = $arg_spec->{name};
        my @next = ("<$arg_name>");
        my @literal = ();
        if ($arg_spec->{optional}) {
            push @next, "(return)";
        }
        if (@$words == 0) {
            if ($arg_spec->{complete}) {
                if (reftype $arg_spec->{complete} eq 'CODE') {
                    push @literal, $arg_spec->{complete}->($partial);
                }
                else {
                    push @literal, @{$arg_spec->{complete}};
                }
            }
            return (\@literal, \@next);
        }

        my $validate = $arg_spec->{verify} // sub { $_[0] };
        my $arg_val;
        eval { $arg_val = $validate->($arg_spec, $words->[0], 1) };
        if (defined $arg_val) {
            shift @$words;
            return complete_words($words, $partial, $arg_spec);
        }
        return([],
            ['** error'.(defined last_error() ? ': '.last_error() : '')]
        );
    }

    if (@$words || length($partial)) {
        return([], [
            '** error: trailing junk "'.join(' ', @$words, $partial).'"'
        ]);
    }

    return([], ['(return)']);
}


# @completions = complete_line($text, $line, $start);
#
#   $text  - (Partial) word to complete.
#   $line  - Input line so far.
#   $start - Position where the $text starts in $line.
#
sub complete_line {
    my ($text, $line, $start) = @_;

    chomp($line);
    my $words   = substr($line, 0, $start);
    #print "<$words> <$text>\n";
    my @words = split(' ', $words);
    my ($literal, $description)
            = complete_words(\@words, $text, { words=>$SYNTAX });
    if (!@$literal && @$description) {
        print "\n";
        print map { "\t$_" } @$description;
        print "\n";
        $TERM->on_new_line();
    }
    return @$literal;
}

# $cols = term_width()
sub term_width {
    my $term = @_ ? shift : $TERM;
    my ($rows, $cols) = $term ? $term->get_screen_size() : (25, 80);
    return $cols;
}

sub clr_to_eol {
    $CLR_TO_EOL //= readpipe('tput el 2>/dev/null');
    return $CLR_TO_EOL;
}

# $fmt = fmt_text($prefix, $text, $maxlen, $indent);
sub fmt_text {
    my ($prefix, $text, $maxlen, $indent) = @_;
    $maxlen //= term_width() - 4;
    $indent //= 0;

    if ($indent > length($prefix) && $prefix !~ /\n$/) {
        $prefix .= ' ' x ($indent - length($prefix));
    }

    my $indent_text = ' ' x $indent;
    my @words = split(' ', $text);
    my $pos = length($prefix);
    my $out = $prefix;
    for my $w (@words) {
        if ($pos + length($w) + 1 > $maxlen) {
            $out .= "\n$indent_text";
            $pos = $indent;
        }
        if ($pos>$indent) { $out .= ' '; $pos++ }
        $out .= $w;
        $pos += length($w);
    }
    $out .= "\n";
}
sub exit_readline {
    return if !$TERM;

    if (defined $HISTORY_FILE) {
        if (! $TERM->WriteHistory($HISTORY_FILE)) {
            print_error("** WARNING: cannot save history to $HISTORY_FILE");
        }
    }
}

sub init_readline {
    my ($prog) = $0 =~ /.*?([^\/]+)$/;
    my %args = (
            'history_lines' => 1000,
            'completion'    => \&complete_line,
            'name'          => $prog,
            @_,
    );
    $args{history_file} //= "$::ENV{HOME}/.$args{name}_history" if $::ENV{HOME};
    $args{prompt}       //= "$args{name}> ";

    $TERM = Term::ReadLine->new( $args{name}, *STDIN, *STDOUT );

    $HISTORY_FILE = $args{history_file};
    if (-f $args{history_file}) {
        if (! $TERM->ReadHistory($HISTORY_FILE)) {
            print_error("** WARNING: cannot read history",
                        " from $HISTORY_FILE\n");
        }
    }

    my $attribs = $TERM->Attribs;
        #$attribs->{attempted_completion_function} = \&rl_completion;
        $attribs->{completion_function} = $args{completion};

    $TERM->set_key('?', 'possible-completions'); # Behave as a Brocade :-)
    #$term->clear_signals();
    $TERM->StifleHistory($args{history_lines});

    $IN  = $TERM->IN  || \*STDIN;
    $OUT = $TERM->OUT || \*STDOUT;

    select $OUT;
    $| = 1;

    $PROMPT = $args{prompt};
    $::SIG{INT} = 'IGNORE';

    return ($TERM, $PROMPT, $IN, $OUT);
}

# $compiled = compile_syntax(\%src);
#
#   Compile a convenient syntax description to a parse tree. The $compiled
#   tree can be used by parse_line().
#
sub compile_syntax {
    my $src = shift;
    my $curr = { words => {} };
    while (my ($key, $spec) = each %$src) {
        _compile_syntax_element($curr, $spec, split(' ', $key)) or return;
    }
    $SYNTAX = $curr->{words};
    return $SYNTAX;
}


# $compiled = _compile_syntax_element($curr, $spec, $word, @rest);
#
#   We've parsed the syntax element of $spec up to $word. Extend
#   the tree at $curr with all the branches of $word.
#
sub _compile_syntax_element {
    my ($curr, $spec, $word, @rest) = @_;

    if ($word) {
        for my $branch (split(qr{\|}, $word)) {
            if (!_compile_branch($curr, $spec, $branch, @rest)) {
                return;
            }
        }
    }
    return $curr;
}

# $compiled = _compile_branch($curr, $spec, $word, @rest);
#
#   We've parsed the syntax element of $spec up to $word. $word
#   is one of the branches at this point. Extend the tree at $curr
#   with $word and whatever follows.
#
sub _compile_branch {
    my ($curr, $spec, $word, @rest) = @_;

    if (substr($word,0,1) ne '$') {
        # We have a literal.
        my $w = $curr->{words} = $curr->{words} // {};
        $curr = $w->{$word} = $w->{$word} // {};
    }
    else {
        # We have a variable.
        my $optional = $word =~ s/^(.*)\?$/$1/;
        my $varname = substr($word,1);
        $curr->{arg} //= {};
        my $a = $curr->{arg};
        %$a = ( %$a, %{$spec->{$word}} );
        $a->{name}     = $varname;
        $a->{optional} = $optional;
        if ($a->{type}) {
            if (my $tspec = $TYPES{$a->{type}}) {
                %$a = (%$tspec, %$a);
            }
            else {
                return print_error("$$a{type}: unknown type\n");
            }
        }
        $curr = $a;
    }
    return _compile_syntax_element($curr, $spec, @rest);
}


# print_error_cond($bool, $msg, ...);
#
#   Always returns false, prints to STDERR if $bool is true,
#   always ends with a newline.
#
sub print_error_cond {
    my $cond = shift;
    my $out = join('', @_);

    chomp($out);

    if ($cond) {
        print STDERR $out, "\n";
        $TERM && $TERM->on_new_line();
    }
    return set_error($out);
}

# print_error($msg, ...);
#
#   Always returns false, always prints to STDERR, always ends
#   with a newline.
#
sub print_error {
    return print_error_cond(1, @_);
}

# set_error($msg, ...);
#
#   Always returns false, set "last" error message.
#
sub set_error {
    $ERROR = join('', @_);
    chomp($ERROR);
    return;
}

# clear_error();
#
#   Always returns true, clear "last" error.
#
sub clear_error {
    $ERROR = undef;
    return @_ == 1 ? $_[0] : @_;
}

# last_error($msg, ...);
#
#   Returns "last" error message.
#
sub last_error {
    return $ERROR;
}

# print_output($msg, ...);
#
#   Print output, through $PAGER if interactive.
#   If any $msg argument is an ARRAY REF, it will be
#   passed to sprintf().
#
sub print_output {
    # Cannot use "sprintf(@$_)" as that will result in a string
    # containing the number of elements of @$_. :-(
    my $out = join('',
        map { 
            ref $_ ? sprintf($$_[0], @{$_}[1..$#$_]) : $_
        } @_
    );
    $out .= "\n" if length($out) && substr($out, -1) ne "\n";

    my $ret = 1;
    my $curr_fh = select;
    if ($TERM && -t $curr_fh) {
        local($::SIG{PIPE}) = 'IGNORE';
        open my $fh, "|$PAGER";
        print $fh $out;
        close $fh;
        $ret = $? == 0;
        $TERM->on_new_line();
    }
    else {
        $ret = print $out;
    }
    return $ret;
}

sub yesno {
    my ($question, $answers) = @_;
    my ($default) = $answers =~ /([A-Z])/;
    $default = 'N' if !defined $default;
    ReadMode 4;
    print "$question ($answers)? $default\b";
    my $answer = undef;
    my $key = '?';
    while (defined ($key = ReadKey(0))) {
        foreach ($key) {
            if ($_ eq "\c[")  { $key = 'n' }
            elsif (/[\r\n ]/) { $key = $default }
        }
        next if index(lc $answers, lc $key) < 0;
        foreach (lc $key) {
            if    ($_ eq "y") { $answer = 1  }
            elsif ($_ eq "n") { $answer = 0  }
            elsif ($_ eq "q") { $answer = -1 }
        }
        last if defined $answer;
    }
    ReadMode 0;
    print "$key\n";
    return $answer;
}

1;

__END__

=pod

=head1 NAME

M6::ReadLine - AMS-IX extensions on top of Term::ReadLine

=head1 SYNOPSIS

 use M6::ReadLine qw( :all );

 init_readline(
            'history_lines' => 1000,
            'completion'    => \&M6::ReadLine::complete_line,
            'name'          => $prog,
            'history_file'  => "$::ENV{HOME}/.${prog}_history";
        );

    ...

 exit_readline();

=head1 DESCRIPTION

AMS-IX extensions on top of Term::ReadLine.

=head1 VARIABLES

=over

=item I<$TERM>

=item I<$IN>

=item I<$OUT>

=item I<$PROMPT>

=item I<$PAGER>

=item I<$HISTORY_FILE>

=item I<$IP_NETWORK>

=back

=head1 FUNCTIONS

=head2 Initialisation / Clean-up

=over

=item X<compile_syntax>B<compile_syntax>

=item X<exit_readline>B<exit_readline>

=item X<init_readline>B<init_readline>

=back

=head2 Validation

=over

=item X<check_bool_arg>B<check_bool_arg>

=item X<check_float_arg>B<check_float_arg>

=item X<check_int_arg>B<check_int_arg>

=item X<check_ip_address_arg>B<check_ip_address_arg>

=item X<check_mac_address_arg>B<check_mac_address_arg>

=item X<match_prefix>B<match_prefix>

=item X<parse_line>B<parse_line>

=item X<parse_words>B<parse_words>

=back

=head2 Completion

=over

=item X<complete_ip_address_arg>B<complete_ip_address_arg>

=item X<complete_line>B<complete_line>

=item X<complete_words>B<complete_words>

=back

=head2 Output / Error Handling

=over

=item X<clear_error>B<clear_error>

=item X<last_error>B<last_error>

=item X<print_error>B<print_error>

=item X<print_error_cond>B<print_error_cond>

=item X<print_output>B<print_output>

=item X<set_error>B<set_error>

=item X<clr_to_eol>B<clr_to_eol>

=back

=head2 Miscellaneous

=over

=item X<yesno>B<yesno>

=back
=head1 SEE ALSO

L<Term::ReadKey|Term::ReadKey>(3pm),
L<Term::ReadLine|Term::ReadLine>(3pm),
L<Term::ReadLine::Gnu|Term::ReadLine::Gnu>(3pm),
L<perl(1)|perl>.

=head1 AUTHOR

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2011.

=head1 COPYRIGHT

Copyright 2011-2016, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
