#!/usr/bin/perl

use Modern::Perl;
use lib qw(.);
use Module::Build;

my $module_name      = 'M6::ARPSponge';
#my ($module_version) = qw(1.00);
my ($module_version) = `head -1 Changelog` =~ /\((.*?)\)/;

my $build = Module::Build->new(
    module_name  => $module_name,
    dist_version => $module_version,
    license      => 'perl',
    dist_author  => 'AMS-IX B.V.',
    license      => 'perl',
    dist_abstract =>
        'automatically "sponge" ARP requests for dead IP addresses',

    configure_requires => { 'Module::Build' => '0.38' },

    build_requires => {
        'Test::More'      => '0.98',
        'Test::Exception' => '0.35',
        'Test::Class'     => '0.35',
        'Devel::Cover'    => '0.66',
    },

    requires => {
        'File::Path'               => '2.09',
        'File::Which'              => '1.09',
        'FindBin'                  => '1.51',
        'Getopt::Long'             => '2.47',
        'IO::File'                 => '1.16',
        'IO::Select'               => '1.22',
        'IO::Socket'               => '1.38',
        'IO::String'               => '1.08',
        'Modern::Perl'             => '1.20150127',
        'Moo'                      => '1.007',
        'Net::Pcap'                => '0.17',
        'NetAddr::IP'              => '4.075',
        'POSIX'                    => '1.38_03',
        'Pod::Usage'               => '1.67',
        'Scalar::Util'             => '1.42',
        'Time::HiRes'              => '1.9726',
        'Types::Standard'          => '1.000005',
        'constant'                 => '1.31',
        'feature'                  => '1.00',
        'overload'                 => '1.22',
        'parent'                   => '0.231',
        'strict'                   => '1.08',
    },
  );

$build->create_build_script;
