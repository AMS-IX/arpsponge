#===============================================================================
#
#       Module:  M6::CLI
#
#  Description:  parse/validate/completion for programs that use ReadLine.
#
#       Author:  Steven Bakker (SB), <steven.bakker@ams-ix.net>
#      Created:  2011-04-21 13:28:04 CEST (as M6::ReadLine)
#
#   Copyright (c) 2011-2015 AMS-IX B.V.; All rights reserved.
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

package M6::CLI;

use parent qw( Exporter );

use Modern::Perl;
use Moo;

use Carp qw( carp croak );
use Data::Dumper;
use FindBin;
use NetAddr::IP;
use Params::Check qw( check );
use POSIX ( );
use Scalar::Util qw( reftype blessed );
use Term::ReadKey;
use Term::ReadLine;
 
my $PAGER = join(' ', qw(
    less --no-lessopen --no-init
         --dumb  --quit-at-eof
         --quit-if-one-screen
));

my %TYPES = (
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
        'verify'   => sub { return $_[0]->clear_error($_[2]) },
        'complete' => []
    },
    'filename' => {
        'verify'   => sub { return $_[0]->clear_error($_[2]) },
        'complete' => \&complete_filename,
    },
);


has IN         => ( is => 'ro', default => sub{ *STDIN } ),
has OUT        => ( is => 'ro', default => sub{ *STDOUT } ),
has name       => ( is => 'ro', default => sub{ $FindBin::Script } );
has term       => ( is => 'rw', writer => '_set_term' );
has ip_network => ( is => 'rw', default => sub { NetAddr::IP->new('0/0') } ),
has syntax     => ( is => 'rw', writer  => '_set_syntax' );
has pager      => ( is => 'rw', default => sub{$PAGER} );
has error      => ( is => 'rw', writer  => '_set_error' );
has prompt     => ( is => 'rw' );

has history_file  => ( is => 'rw' );
has history_lines => ( is => 'rw', default => sub {1000} );

after history_lines => sub {
    # Make sure we propagate the value of history_lines down to the
    # Term::ReadLine object.
    return if @_ != 2;
    my ($self, $val) = @_;
    return if ! $self->term->Features->{'stiflehistory'};
    $self->term->StifleHistory(int $val);
};

around ip_network => sub {
    my $orig = shift;
    my $self = shift;
    if (@_) {
        my $val = shift;
        my $ip = NetAddr::IP->new($val)
            or croak "ip_network(): bad IP address $val\n";
        return $orig->($self, $ip);
    }
    return $orig->($self);
};


sub BUILD {
    my ($self, $args) = @_;

    # Create the Term::ReadLine object.
    my $term = Term::ReadLine->new( $self->name, $self->IN, $self->OUT );
    $self->_set_term($term);

    # Set a default prompt if none is given.
    if (!defined $self->prompt) {
        $self->prompt($self->name."> ");
    }

    # Make sure history_lines propagates to the underlying ReadLine object.
    $self->history_lines($self->history_lines);


    #$self->set_history_lines($self->history_lines);

    if (!defined $self->history_file) {
        $self->history_file("$::ENV{HOME}/.".$self->name."_history");
    }

    if ($term->Features->{'minline'}) {
        $term->MinLine(1);
    }

    my $attribs = $term->Attribs;

    my $completion = $args->{completion} // \&complete_line;
    $attribs->{completion_function} = sub { $completion->($self, @_) };

    # Try to behave as a Brocade :-)
    if ($term->ReadLine =~ /::Gnu$/) {
        $term->set_key('?', 'possible-completions');
    }
    elsif ($term->ReadLine =~ /::Perl$/) {
        $term->bind('?', 'possible-completions');
    }

    $| = 1;
    $::SIG{INT} = 'IGNORE';

    return $self;
}

# ===========================================================================
#
#   TYPE FUNCTIONS
#
# ===========================================================================

# register a user type.
sub register_type {
    my $self = shift;
    my $name = lc shift;
    my $definition = shift;

    if (defined $TYPES{$name}) {
        carp "register_type(): '$name' redefined"; 
    }
    if (ref $definition eq 'HASH') {
        croak "register_type(): '$name': definition is not a HASH ref";
    }
    my @type_keys = sort keys %$definition;
    state $valid_type_keys = {map { $_ => 1 } qw( verify complete )};
    for my $t (@type_keys) {
        if (!$valid_type_keys->{$t}) {
            croak "register_type(): '$name' definition contains bad key '$t'";
        }
    }

    $TYPES{$name} = $definition;
    return;
}


sub get_type {
    return $TYPES{lc $_[1]};
}


sub get_type_names {
    return sort keys %TYPES;
}


# ===========================================================================
#
#   HISTORY FUNCTIONS
#
# ===========================================================================

sub read_history {
    my $self  = shift;
    my $fname = @_ ? shift : $self->history_file;

    my $term = $self->term || return;

    return if ! $term->Features->{'readHistory'};

    return if $fname eq '';
    return if ! -f $fname;

    if (! $term->ReadHistory($fname)) {
        $self->print_error("** WARNING: cannot read history from $fname");
    }
}


sub write_history {
    my $self  = shift;
    my $fname = @_ ? shift : $self->history_file;

    my $term = $self->term || return;

    return if ! $term->Features->{'writeHistory'};

    return if $fname eq '';

    if (! $term->WriteHistory($fname)) {
        $self->print_error("** WARNING: cannot save history to $fname");
    }
}


# ===========================================================================
#
#   VALIDATION FUNCTIONS
#
# ===========================================================================

sub _is_valid_num {
    my $self = shift;
    my $func = shift;
    my $arg  = shift;
    my $err_s;
    my %opts = (err => \$err_s, min => undef, max => undef, inclusive => 1, @_);

    if (!defined $arg || length($arg) == 0) {
        ${$opts{err}} = 'not a valid number';
        return;
    }

    my ($num, $unparsed) = $func->($arg);
    if ($unparsed) {
        ${$opts{err}} = 'not a valid number';
        return;
    }

    if ($opts{inclusive}) {
        if (defined $opts{min} && $num < $opts{min}) {
            ${$opts{err}} = 'too small';
            return;
        }
        if (defined $opts{max} && $num > $opts{max}) {
            ${$opts{err}} = 'too large';
            return;
        }
    }
    else {
        if (defined $opts{min} && $num <= $opts{min}) {
            ${$opts{err}} = 'too small';
            return;
        }
        if (defined $opts{max} && $num >= $opts{max}) {
            ${$opts{err}} = 'too large';
            return;
        }
    }
    ${$opts{err}} = '';
    return $num;
}


# (err => \$err_s, min => undef, max => undef, inclusive => 1)
sub is_valid_int   { return shift->_is_valid_num(\&POSIX::strtol, @_) }
sub is_valid_float { return shift->_is_valid_num(\&POSIX::strtod, @_) }

sub is_valid_ip {
    my $self = shift;
    my $arg = shift;
    my $err_s;
    my %opts = (err => \$err_s, network => undef, @_);

    if (!defined $arg || length($arg) == 0) {
        ${$opts{err}} = q/"" is not a valid IPv4 address/;
        return;
    }

    my $ip = NetAddr::IP->new($arg);
    if (!$ip) {
        ${$opts{err}} = qq/"$arg" is not a valid IPv4 address/;
        return;
    }
    
    return $ip->addr() if !$opts{network};
   
    if (my $net = NetAddr::IP->new($opts{-network})) {
        return $ip->addr() if $net->contains($ip);
        ${$opts{err}} = qq/$arg is out of range /.$net->cidr();
        return;
    }
    else {
        ${$opts{err}} = qq/** INTERNAL ** is_valid_ip(): -network /
                       . qq/argument "$opts{network}" is not valid/;
        warn ${$opts{err}};
        return;
    }
}


# $byte = check_int_arg(\%spec, $arg, $silent_flag);
sub check_int_arg {
    my ($self, $spec, $arg, $silent) = @_;
    my $argname = $spec->{name} // 'num';

    my $err;
    my $val = $self->is_valid_int($arg, %$spec, err=>\$err);
    if (defined $val) {
        return $self->clear_error($val);
    }
    return $self->print_error_cond(!$silent, qq{"$arg" is $err for $argname parameter});
}

# $percentage = $self->check_float_arg({min=>0, max=>100}, $arg, $silent_flag);
sub check_float_arg {
    my ($self, $spec, $arg, $silent) = @_;
    my $argname = $spec->{name} // 'num';

    my $err;
    my $val = $self->is_valid_float($arg, %$spec, err=>\$err);
    if (defined $val) {
        return $self->clear_error($val);
    }
    return $self->print_error_cond(!$silent, qq{"$arg" is $err for $argname parameter});
}

# $bool = $self->check_bool_arg($min, $max, $arg, $silent_flag);
sub check_bool_arg {
    my ($self, $spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'bool';

    if ($arg =~ /^(1|yes|true|on)$/i) {
        return $self->clear_error(1);
    }
    elsif ($arg =~ /^(0|no|false|off)$/i) {
        return $self->clear_error(0);
    }
    return $self->print_error_cond(!$silent,
                qq{$argname: "$arg" is not a valid boolean});
}

sub check_ip_address_arg {
    my ($self, $spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'ip';

    my $err;
    $arg = $self->is_valid_ip($arg, network=>$self->ip_network->cidr, err=>\$err);
    if (defined $arg) {
        return $self->clear_error($arg);
    }
    return $self->print_error_cond(!$silent, qq{$argname: $err});
}

sub check_mac_address_arg {
    my ($self, $spec, $arg, $silent) = @_;

    my $argname = $spec->{name} // 'mac';

    if ($arg =~ /^(?:[\da-f]{1,2}[:.-]){5}[\da-f]{1,2}$/i
        || $arg =~ /^(?:[\da-f]{1,4}[:.-]){2}[\da-f]{1,4}$/i
        || $arg =~ /^[\da-f]{1,12}$/i) {
        return $self->clear_error($arg);
    }
    else {
        $self->print_error_cond($silent,
            qq{$argname: "$arg" is not a valid MAC address});
        return;
    }
}


# ===========================================================================
#
#   INPUT FUNCTIONS
#
# ===========================================================================

# Wrap around Term::ReadLine->readline() providing a default prompt.
sub readline {
    my $self = shift;
    my $prompt = @_ ? shift : $self->prompt();
    return $self->term->readline($prompt);
}

# $answer = yesno($question, "Ynq");
sub yesno {
    my $self = shift;

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
        foreach (lc $key) {
            if (index(lc $answers, $_) >= 0) {
                if    ($_ eq "y") { $answer = +1  }
                elsif ($_ eq "n") { $answer =  0  }
                elsif ($_ eq "q") { $answer = -1 }
            }
        }
        last if defined $answer;
    }
    ReadMode 0;
    print "$key\n";
    $self->term && $self->term->on_new_line();
    return $answer;
}


# ===========================================================================
#
#   COMPLETION FUNCTIONS
#
# ===========================================================================

sub complete_ip_address_arg {
    my $self = shift;
    my $partial = shift;

    my $network   = $self->ip_network->short;
    
    my $fixed_octets = int($self->ip_network->masklen / 8);

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

sub complete_filename {
    my $self = shift;
    my $partial = shift;
    my $attribs = $self->term->Attribs;
    my @list;
    my $state = 0;
    my $func = $attribs->{filename_completion_function} or return;
    while (my $func->($partial, $state)) {
        push @list, $f;
        $state = 1;
    }
    return @list;
}


# @completions = complete_line($text, $line, $start);
#
#   $text  - (Partial) word to complete.
#   $line  - Input line so far.
#   $start - Position where the $text starts in $line.
#
sub complete_line {
    my ($self, $text, $line, $start) = @_;

    chomp($line);
    my $words = substr($line, 0, $start);
    my @words = split(' ', $words);
    my ($literal, $description) 
            = $self->complete_words(\@words, $text, { words=>$self->syntax });

    if (!@$literal && @$description) {
        print "\n", map { "\t$_\n" } @$description;
        $self->redraw;
    }

    return @$literal;
}


# @completions = $term->complete_words(\@words, $partial, \%syntax);
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
    my $self       = shift;
    my $words      = shift;
    my $partial    = shift;
    my $syntax     = shift;

    if (my $word_list = $syntax->{words}) {
        if (!@$words) {
            # We've arrived at the end of the line.
            my $l = length $partial;
            my @match = grep { substr($_,0, $l) eq $partial } keys %$word_list;
            return (\@match, \@match);
        }

        my @next = sort grep { length $_ } keys %$word_list;

        my @literals = @next;
        if (exists $word_list->{''}) {
            push @literals, '';
            push @next, '(return)';
        }
        my $match = $self->match_unique_prefix($words->[0], $word_list, silent_err => 1);
        if (defined $match) {
            shift @$words;
            return $self->complete_words($words, $partial, $word_list->{$match});
        }
        else {
            return ([], [$self->error]);
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
                    @literal = $arg_spec->{complete}->($self, $partial);
                }
                else {
                    @literal = @{$arg_spec->{complete}};
                }
            }
            if (length($partial) && !@literal) {
                return ([], []);
            }
            return (\@literal, \@next);
        }

        my $validate = $arg_spec->{verify} // sub { $_[0] };
        my $arg_val;
        eval { $arg_val = $validate->($self, $arg_spec, $words->[0], 1) };
        if (defined $arg_val) {
            shift @$words;
            return $self->complete_words($words, $partial, $arg_spec);
        }
        else {
            return([],
                ['** error'.(defined $self->error() ? ': '.$self->error() : '')]
            );
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


# ===========================================================================
#
#   PARSING FUNCTIONS
#
# ===========================================================================

#
# $word = $term->match_unique_prefix(
#   $input,
#   [words => ] { \@words | \%words }
#   [, silent_err => $silent_err]
#   [, err_prefix => $err_prefix]
# );
#
sub match_unique_prefix {
    my $self = shift;
    my $input = lc shift;

    my $words;

    if (@_ % 2 == 1) { $words = shift }

    my $opts = check({
        silent_err => { store => \(my $silent_err = 0) },
        err_prefix => { store => \(my $err_prefix = '') },
        words      => { store => \$words },
    }, {@_}, 1);

    if (ref $words eq 'HASH') {
        $words = [keys %$words];
    }

    my $word;
    my @match = grep { substr($_, 0, length($input)) eq $input } sort @$words;
    if (@match > 1) {
        return $self->print_error_cond(!$silent_err,
            qq{** $err_prefix"$input" is ambiguous; matches: }. join(', ', @match)
        );
    }
    elsif (@match == 0) {
        return $self->print_error_cond(!$silent_err,
            qq{** $err_prefix"$input" invalid; expected: }.join(", ", sort @$words)
        );
    }
    return $self->clear_error($match[0]);
}

#
# $ok = $self->parse_line($line, \@parsed, \%args);
#
#   Parse the input line in $line against $self->syntax (compiled syntax). All
#   parsed, literal command words (i.e. neither argument nor option) are
#   stored in @parsed. All arguments and options are stored in %args.
#
#   Returns 1 on success, undef on failure.
#
sub parse_line {
    my ($self, $line, $parsed, $args) = @_;
    chomp($line);
    my @words = split(' ', $line);
    $args->{'-options'} = [];
    return $self->_parse_words(\@words, { words => $self->syntax }, $parsed, $args);
}

# $ok = $self->_parse_words(\@words, $syntax, \@parsed, \%args);
#
#   Parse the words in @words against $syntax (compiled syntax). All
#   parsed, literal command words (i.e. neither argument nor option) are
#   stored in @parsed. All arguments and options are stored in %args.
#
#   Returns 1 on success, undef on failure.
#
sub _parse_words {
    my $self    = shift;
    my $words   = shift;
    my $syntax  = shift;
    my $parsed  = shift;
    my $args    = shift;

    # Command line options (--something, -s), are stored
    # in the '-options' array in %$args. They'll be parsed
    # later on.
    while (@$words && $$words[0] =~ /^-{1,2}./) {
        push @{$args->{-options}}, shift @$words;
    }

    if (my $word_list = $syntax->{words}) {

        if (!@$words) {
            if (exists $word_list->{''}) {
                return 1;
            }
            else {
                return $self->print_error(
                    "** @$parsed: too few arguments\n** expected one of: ",
                    join(q{, }, sort grep { length $_ } keys %$word_list)
                );
            }
        }
        my $match = $self->match_unique_prefix(
            $words->[0], $word_list,
            silent_err => 0,
            err_prefix => "@$parsed: "
        ) or return;

        if (defined $match) {
            push @$parsed, $match;
            shift @$words;
            return $self->_parse_words(
                $words, $word_list->{$match}, $parsed, $args
            );
        }
    }
    elsif (my $arg_spec = $syntax->{arg}) {
        my $arg_name = $arg_spec->{name};
        $args->{$arg_name} = $arg_spec->{default};
        if (!@$words) {
            if ($arg_spec->{optional}) {
                return $self->_parse_words($words, $arg_spec, $parsed, $args);
            }
            else {
                return $self->print_error("** @$parsed: missing <$arg_name> argument");
            }
        }
        my $arg_val;
        if (my $validate = $arg_spec->{verify}) {
            eval { $arg_val = $validate->($self, $arg_spec, $words->[0]) };
            if (!defined $arg_val && $@) { 
                return $self->print_error(
                    qq{** @$parsed: internal error on parsing '$$words[0]': $@}
                );
            }
        }
        else {
            $arg_val = $words->[0];
        }
        return if ! defined $arg_val;
        $args->{$arg_name} = $arg_val;
        shift @$words;
        return $self->_parse_words($words, $arg_spec, $parsed, $args);
    }
    elsif (@$words) {
        return $self->print_error(
            qq{** @$parsed: expected end of line instead of "$$words[0]"\n}
        );
    }
    return 1;
}


# ===========================================================================
#
#   MISCELLANEOUS FUNCTIONS
#
# ===========================================================================


sub redraw {
    my $self = shift;

    my $term = $self->term or return;

    my $rl_implementation = $term->ReadLine;

    if ($rl_implementation =~ /::Gnu/) {
        $term->on_new_line;
    }
    elsif ($rl_implementation =~ /::Perl/) {
        $readline::force_redraw = 1;
        readline::redisplay();
    }
}


# $cols = $term->term_width()
sub term_width {
    my $self = shift;
    my ($cols, $rows, $xpx, $ypx) = GetTerminalSize();
    return $cols || 80;
}


# $clr_to_eol = CLASS->clr_to_eol();
sub clr_to_eol {
    state $CLR_TO_EOL = readpipe('tput el 2>/dev/null');
    return $CLR_TO_EOL;
}


# ===========================================================================
#
#   OUTPUT FUNCTIONS
#
# ===========================================================================


# $fmt = CLASS->fmt_text( [text =>] $text, [ opt => val, ... ]);
sub fmt_text {
    my $self = shift;

    my $text;

    if (@_ % 2 == 1) { 
        $text = shift;
    }

    my $opts = check({
            prefix => { store => \(my $prefix = '') },
            maxlen => { store => \(my $maxlen = $self->term_width()-4) },
            indent => { store => \(my $indent = 0) },
            text   => { store => \$text },
        }, {@_}, 1);

    if ($prefix !~ /\n$/) {
        # The prefix does not end in a newline.
        my ($prefix_tail) = $prefix =~ /^(.*)\z/m;
        if (length($prefix_tail) < $indent) {
            # The prefix is shorter than the indent, so pad
            # it with spaces until it has the correct length.
            $prefix .= ' ' x ($indent - length($prefix_tail));
        }
    }

    my $indent_text = ' ' x $indent;
    my @words = split(' ', $text);

    my $out = $prefix;
    my $pos_in_line;
    if ($out =~ /^(.+?)\z/m) {
        $pos_in_line = length($1);
    }
    else {
        $out .= $indent_text;
        $pos_in_line = $indent;
    }

    # Push words onto $out, making sure each line doesn't run over
    # $maxlen.
    for my $w (@words) {
        if ($pos_in_line + length($w) + 1 > $maxlen) {
            # Next word would make the line run over $maxlen,
            # so insert a newline.
            $out .= "\n$indent_text";
            $pos_in_line = $indent;
        }
        if ($out =~ /\S+$/) {
            # Always eparate words with a space.
            $out .= ' ';
            $pos_in_line++;
        }
        $out .= $w;
        $pos_in_line += length($w);
    }
    $out .= "\n";
    return $out;
}


# print_output($msg, ...);
#
#   Print output, through pager if interactive.
#
sub print_output {
    my $self = shift;
    my $out = join('', @_);
       $out .= "\n" if $out !~ /\n\Z/ && length($out);

    my $ret = 1;
    my $curr_fh = select;
    if ($self->term && -t $curr_fh) {
        local($::SIG{PIPE}) = 'IGNORE';
        open my $pager, "|".$self->pager;
        $pager->print($out);
        close $pager;
        $ret = $? == 0;
        $self->term->on_new_line();
    }
    else {
        $ret = print $out;
    }
    return $ret;
}


# ============================================================================
#
#   SYNTAX COMPILATION
#
# ============================================================================

# $compiled = $term->compile_syntax(\%src);
#
#   Compile a convenient syntax description to a parse tree. The $compiled
#   tree can be used by parse_line().
#
sub compile_syntax {
    my $self = shift;
    my $src = shift;

    my $curr = { words => {} };
    while (my ($key, $spec) = each %$src) {
        $self->_compile_syntax_element($curr, $spec, split(' ', $key)) or return;
    }
    $self->_set_syntax($curr->{words});
    return $self->syntax;
}


# $compiled = $term->_compile_syntax_element($curr, $spec, $word, @rest);
#
#   We've parsed the syntax element of $spec up to $word. Extend
#   the tree at $curr with all the branches of $word.
#
sub _compile_syntax_element {
    my ($self, $curr, $spec, $word, @rest) = @_;

    if ($word) {
        for my $branch (split(qr{\|}, $word)) {
            if (!$self->_compile_branch($curr, $spec, $branch, @rest)) {
                return;
            }
        }
    }
    return $curr;
}


# $compiled = $term->_compile_branch($curr, $spec, $word, @rest);
#
#   We've parsed the syntax element of $spec up to $word. $word
#   is one of the branches at this point. Extend the tree at $curr
#   with $word and whatever follows.
#
sub _compile_branch {
    my ($self, $curr, $spec, $word, @rest) = @_;

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
            if (my $tspec = $self->get_type($a->{type})) {
                %$a = (%$tspec, %$a);
            }
            else {
                return $self->print_error("$$a{type}: unknown type\n");
            }
        }
        $curr = $a;
    }
    return $self->_compile_syntax_element($curr, $spec, @rest);
}


# ===========================================================================
#
# ERROR HANDLING
#
# ===========================================================================

# print_error_cond($bool, $msg, ...);
#
#   Always returns false, prints to STDERR if $bool is true,
#   always ends with a newline.
#
sub print_error_cond {
    my $self = shift;
    my $cond = shift;
    my $out = join('', @_);

    chomp($out);

    if ($cond) {
        say STDERR $out;
        $self->term && $self->term->can('on_new_line') && $self->term->on_new_line();
    }
    return $self->set_error($out);
}


# print_error($msg, ...);
#
#   Always returns false, always prints to STDERR, always ends
#   with a newline.
#
sub print_error {
    my $self = shift;
    return $self->print_error_cond(1, @_);
}

# set_error($msg, ...);
#
#   Always returns false, set "last" error message.
#
sub set_error {
    my $self = shift;
    $self->_set_error(join('', @_));
    return;
}

# clear_error();
#
#   Always returns true, clear "last" error.
#
sub clear_error {
    my $self = shift;
    $self->_set_error(undef);
    return @_ == 1 ? $_[0] : @_;
}

1;

__END__

=pod

=head1 NAME

M6::CLI - CLI parser using Term::ReadLine

=head1 SYNOPSIS

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

 while (1) {
    my $input = $TERM->readline('~> ');
    last if !defined $input;

    next if $input =~ /^\s*(?:#.*)?$/;

    if (parse_line($input, \(my @parsed), \(my %args))) {
        print "@parsed\n";
    }
 }

 ...

 exit_readline();

=head1 DESCRIPTION

AMS-IX extensions on top of Term::ReadLine.

=head1 VARIABLES

=over

=item I<$IN>

=item I<$OUT>

=item I<$PROMPT>

=item I<$PAGER>

=back

=head1 FUNCTIONS

=head2 Initialisation / Clean-up

=over

=item B<compile_syntax>
X<compile_syntax>

=item B<exit_readline>
X<exit_readline>

=item B<init_readline>
X<init_readline>

=back

=head2 Validation

=over

=item B<check_bool_arg>
X<check_bool_arg>

=item B<check_float_arg>
X<check_float_arg>

=item B<check_int_arg>
X<check_int_arg>

=item B<check_ip_address_arg>
X<check_ip_address_arg>

=item B<check_mac_address_arg>
X<check_mac_address_arg>

=item B<match_unique_prefix>
X<match_unique_prefix>

=item B<parse_line>
X<parse_line>

=item B<is_valid_int>
X<is_valid_int>

=item B<is_valid_float>
X<is_valid_float>

=item B<is_valid_ip>
X<is_valid_ip>

=back

=head2 Completion

=over

=item B<complete_ip_address_arg>
X<complete_ip_address_arg>

=item B<complete_line>
X<complete_line>

=item B<complete_words>
X<complete_words>

=back

=head2 Output / Error Handling

=over

=item B<fmt_text> ( I<text>, [ I<param> =E<gt> I<val>, ... ] )
X<fmt_text>

=item B<fmt_text> ( B<text> =E<gt> I<text>, [ I<param> =E<gt> I<val>, ... ] )

Parameters: 

=over

=item B<prefix> =E<gt> I<string>

=item B<maxlen> =E<gt> I<int>

=item B<indent> =E<gt> I<int>

=back

Format I<text>, so that it wraps at B<maxlen> columns
(default is terminal width minus 4), with the first line
prefixed with B<prefix> and the body indented by B<indent>
spaces.

For non-empty prefixes, there is always a space between
the prefix and the I<text>.

The return value is the reflowed string, which is always
terminated by a newline.

Example:

   fmt_text( ""
    -prefix => 'MONKEY, n.',
    -text   => 'An arboreal animal which makes itself'
              .' at home in genealogical trees.'
    -maxlen => 4,
    -indent => 10,
   );

Result:

    |0--------1---------2---------3|
    |1--------0---------0---------0|
    |MONKEY, n. An arboreal animal |
    |    which makes itself at home|
    |    in genealogical trees.    |

Note that the lines in the resulting string are not guaranteed
to stay within the B<maxlen> limit: if a single word exceeds
the length limit, it is added on a (possibly indented) line on
its own.

Example:

   fmt_text( ""
    -prefix => 'MONKEY, n.',
    -text   => 'An-arboreal-animal-which-makes itself'
              .' at home in genealogical trees.'
    -maxlen => 4,
    -indent => 10,
   );

Result:

    |0--------1---------2---------3|
    |1--------0---------0---------0|
    |MONKEY, n.                    |
    |   An-arboreal-animal-which-makes
    |   itself at home in          |
    |   genealogical trees.        |

=item B<clear_error>
X<clear_error>

=item B<print_error>
X<print_error>

=item B<print_error_cond>
X<print_error_cond>

=item B<print_output>
X<print_output>

=item B<set_error>
X<set_error>

=item B<clr_to_eol>
X<clr_to_eol>

Return the string that will clear the current line on the terminal from the cursor
position onwards, i.e. return the terminal's C<el> string.

=back

=head2 Miscellaneous

=over

=item B<yesno> ( I<question>, I<answer> )
X<yesno>

Ask I<question> and read a yes/no answer.

The I<answers> string should contain a combination of the letters C<y>,
C<n>, and C<q>, corresponding to resp. C<yes>, C<no>, C<quit>. If any
of the letters is capitalised, it is taken to be the default answer
if the user hits Enter or Space (if none given, the default is C<N>).

The return value is an integer:

=over

=item C<+1>

Yes.

=item C<0>

No.

=item C<-1>

Quit.

=back

=back

=head1 SEE ALSO

L<less>(1),
L<Term::ReadKey>(3pm),
L<Term::ReadLine>(3pm),
L<Term::ReadLine::Gnu>(3pm).

=head1 AUTHOR

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2011-2015.

=head1 COPYRIGHT

Copyright 2011-2015, AMS-IX B.V.
Distributed under GPL and the Artistic License 2.0.

=cut
