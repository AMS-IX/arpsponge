#!perl

use strict;
use warnings;

use Test::More;
use Test::Compile;

my @pms = all_pm_files;
my @pls = all_pl_files(qw( bin script cgi-bin ));

plan tests => int(@pms) + int(@pls);

pm_file_ok($_) for @pms;
pl_file_ok($_) for @pls;
