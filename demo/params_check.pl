#!/usr/bin/perl

use Modern::Perl;
use Params::Check qw( check last_error );

sub foo {
    my $args = check({
            prefix => { store => \(my $prefix = '(default="")') },
            maxlen => { store => \(my $maxlen = '(default=76)') },
            indent => { store => \(my $indent = '(default=0)')  },
        }, {@_}, 1);

    if (!$args) {
        say "\nERR: ".last_error()."\n";
    }
    say "prefix=<$prefix>; maxlen=<$maxlen>; indent=<$indent>";
}

foo( prefix => 'prefix1' );
foo( maxlen => 2 );
foo( indent => 3 );
foo( sprefix => 'prefix4', maxlen => 4, indent => 4, crinkle => 4 );
