# @(#)$Id$
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
#   Copyright (c) 2011 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6::ReadLine;

use strict;
use warnings;
use base qw( Exporter );
use Term::ReadLine;
use NetAddr::IP;
use M6::ARP::Util qw( :all );
use Data::Dumper;
use Scalar::Util qw( reftype );

BEGIN {
	use Exporter;

    our $VERSION     = '1.00';
	my  @check_func  = qw(
            check_ip_address_arg  complete_ip_address_arg
            check_int_arg
            check_float_arg
            check_bool_arg
        );
	my  @gen_functions = qw( compile_syntax init_readline
                             parse_line
                             print_error print_output );
	my  @functions   = (@check_func, @gen_functions);
    my  @vars        = qw( $TERM $IN $OUT $PROMPT $PAGER );
	our @EXPORT_OK   = (@functions, @vars);
	our @EXPORT      = @gen_functions;
	our %EXPORT_TAGS = ( func => \@functions, check => \@check_func,
                         all => \@EXPORT_OK, vars => \@vars );
}

our $TERM        = undef;
our $IN          = \*STDIN;
our $OUT         = \*STDOUT;
our $PROMPT      = '';
our $IP_NETWORK  = NetAddr::IP->new('0/0');
our $SYNTAX      = {};
our $PAGER       = join(' ', qw(
                        less --no-lessopen --no-init
                             --dumb  --quit-at-eof
                             --quit-if-one-screen
                    ));

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
    );

# $byte = check_int_arg(\%spec, $arg, 'byte');
sub check_int_arg {
    my ($spec, $arg, $silent) = @_;
    my $min     = $spec->{min};
    my $max     = $spec->{max};
    my $argname = $spec->{name} // 'num';

    my $err;
    if (my $val = is_valid_int($arg, -min=>$min, -max=>$max, -err=>\$err)) {
        return $val;
    }
    $silent or print_error(qq{$argname: "$arg": $err});
    return;
}

# $percentage = check_int_arg({min=>0, max=>100}, $arg, 'percentage');
sub check_float_arg {
    my ($spec, $arg, $silent) = @_;
    my $min     = $spec->{min};
    my $max     = $spec->{max};
    my $argname = $spec->{name} // 'num';

    my $err;
    if (my $val = is_valid_float($arg, -min=>$min, -max=>$max, -err=>\$err)) {
        return $val;
    }
    $silent or print_error(qq{$argname: "$arg": $err});
    return;
}

# $bool = check_bool_arg($min, $max, $arg, 'dummy');
sub check_bool_arg {
    my ($spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'bool';

    if ($arg =~ /^(1|yes|true|on)$/i) {
        return 1;
    }
    elsif ($arg =~ /^(0|no|false|off)$/i) {
        return 0;
    }
    $silent or print_error(qq{$argname: "$arg" is not a valid boolean});
    return;
}

sub check_ip_address_arg {
    my ($spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'ip';

    my $err;
    if ($arg = is_valid_ip($arg, -network=>$IP_NETWORK->cidr, -err=>\$err)) {
        return $arg;
    }
    $silent or print_error(qq{$argname: $err});
    return;
}

sub check_mac_address_arg {
    my ($spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'mac';

    if ($arg =~ /^(?:[\da-f]{1,2}[:.-]){5}[\da-f]{1,2}$/i
        || $arg =~ /^(?:[\da-f]{1,4}[:.-]){2}[\da-f]{1,4}$/i
        || $arg =~ /^[\da-f]{1,12}$/i) {
        return $arg;
    }
    else {
        $silent or print_error(qq{$argname: "$arg" is not a valid MAC address});
        return;
    }
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
        else {
            return grep { length($_) == length($fixed)+2 } @completions;
        }
    }
    else {
        return ("$fixed.", "$fixed.x");
    }
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
    while (@$words && $$words[0] =~ /^-{1,2}/) {
        push @{$args->{-options}}, shift @$words;
    }

    if (my $word_list = $syntax->{words}) {
        my $words_str = join(q{}, 
                            map { "  $_\n" } 
                                sort grep { length $_ } keys %$word_list
                        );
        if (!@$words) {
            if (exists $word_list->{''}) {
                return 1;
            }
            else {
                return print_error("@$parsed: expected one of:\n$words_str");
            }
        }
        my $w = $words->[0];
        my $l = length($w);
        my @match = grep { substr($_,0, $l) eq $w } keys %$word_list;
        if (@match == 1) {
            push @$parsed, $match[0];
            shift @$words;
            return parse_words($words, $word_list->{$match[0]},
                               $parsed, $args);
        }
        elsif (@match > 1) {
            return print_error(
                        qq{ambibuous input "$$words[0]"; },
                        qq{matches: }, join(', ', sort @match), "\n"
                    );
        }
        else {
            return print_error(
                        qq{invalid input "$$words[0]"; },
                        qq{expected one of:\n$words_str}
                    );
        }
    }
    elsif (my $arg_spec = $syntax->{arg}) {
        my $arg_name = $arg_spec->{name};
        $args->{$arg_name} = $arg_spec->{default};
        if (!@$words) {
            if ($arg_spec->{optional}) {
                return parse_words($words, $arg_spec, $parsed, $args);
            }
            else {
                return print_error("@$parsed: missing <$arg_name> argument");
            }
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
    elsif (@$words) {
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
        elsif (@match > 1) {
            return ([],
                    [qq{** "$$words[0]" ambiguous; matches: }
                    . join(', ', sort @match)]
                );
        }
        else {
            return([],
                   [qq{** "$$words[0]" invalid; expected: }
                   . join(", ", sort @next)]
                );
        }
    }
    elsif (my $arg_spec = $syntax->{arg}) {
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
        else {
            return([], ['** error']);
        }
    }
    elsif (@$words || length($partial)) {
        return([], [
                '** error: trailing junk "'.join(' ', @$words, $partial).'"'
            ]);
    }
    else {
        return([], ['(return)']);
    }
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

sub init_readline {
    my ($prog) = $0 =~ /.*?([^\/]+)$/;
    my %args = (
            'history_lines' => 1000,
            'completion'    => \&complete_line,
            'name'          => $prog,
            @_,
    );
    $args{history_file} //= "$::ENV{HOME}/.$args{name}_history";
    $args{prompt}       //= "$args{name}> ";

    $TERM = Term::ReadLine->new( $args{name}, *STDIN, *STDOUT );

    if (-f $args{history_file}) {
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

# print_error($msg, ...);
#
#   Always returns false, always prints to STDERR, always ends
#   with a newline.
#
sub print_error {
    my $out = join('', @_);
       $out .= "\n" if $out !~ /\n\Z/;
    print STDERR $out;
    $TERM && $TERM->on_new_line();
    return;
}

# print_output($msg, ...);
#
#   Print output, through $PAGER if interactive.
#
sub print_output {
    my $out = join('', @_);
       $out .= "\n" if $out !~ /\n\Z/;

    if ($TERM) {
        open(MORE, "|$PAGER");
        print MORE $out;
        close MORE;
    }
    else {
        print $out;
    }
    $TERM && $TERM->on_new_line();
}


1;

__END__

=pod

=head1 NAME

MODNAME - singing and dancing module

=head1 SYNOPSIS

 use MODNAME;

=head1 DESCRIPTION

=head1 CONSTANTS

=head1 CONSTRUCTORS

=head1 METHODS

=head1 FUNCTIONS

=head1 EXAMPLES

=head1 FILES

=head1 SEE ALSO

L<perl(1)|perl>.

=head1 CAVEATS

=head1 AUTHOR

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2011.

=cut

