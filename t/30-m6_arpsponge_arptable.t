#!perl

use Modern::Perl;
use Test::Class;
use FindBin;

use lib "$FindBin::Bin/lib";

use M6_ARPSponge_ARPTable_Test;

Test::Class->runtests();
