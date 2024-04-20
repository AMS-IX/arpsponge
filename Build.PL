#!/usr/bin/perl

use strict;
use warnings;
use lib qw(.);
use Module::Build;

my $module_name      = 'M6-ARPSponge';
#my ($module_version) = qw(1.00);
my ($module_version) = `head -1 Changelog` =~ /\((.*?)\)/;

my $build = Module::Build->new(
    module_name  => $module_name,
    dist_version => $module_version,
    license      => 'perl',
    dist_author  => 'AMS-IX B.V.',
    license      => 'perl',
    dist_abstract =>
        'provide Perl interface to My.AMS-IX REST API',

    configure_requires => { 'Module::Build' => '0.38' },

    build_requires => {
        'Test::More'     => '0.98',
        'Test::Class'    => '0.35',
        'Devel::Cover'   => '0.66',
    },

    requires => {
        'strict'         => '1.04',
        'warnings'       => '1.06',
    },
  );

$build->create_build_script;
