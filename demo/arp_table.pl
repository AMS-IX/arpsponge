#!/usr/bin/perl

use lib qw( ../lib );

use Modern::Perl;

 use M6::ARPSponge::ARPTable;
 use M6::ARPSponge::Util qw(
    ip2hex hex2ip mac2hex hex2mac
    format_time
 );

 my $table = M6::ARPSponge::ARPTable->new();

 my $ip  = '10.0.0.1';
 my $mac = '52:54:00:85:3c:0a';

 # Add or update ARP entry
 $table->update( ip2hex($ip), mac2hex($mac) );

 # Perform lookup of an ARP entry
 my ($hex_mac, $mtime) = $table->lookup( ip2hex($ip) );

 if (defined $hex_mac) {
    say $ip, ' -> ', hex2mac($hex_mac),
        ' (', format_time($mtime), ')';
 }

 # Delete an ARP entry.
 $table->delete( ip2hex($ip) );

 # Clear the whole ARP table.
 $table->clear();

 # Access the internal ARP HASH table.
 my $hash = $table->table;

 for my $hex_ip (sort { $a cmp $b } keys %$hash) {
    my ($hex_mac, $mtime) = @{$hash->{$hex_ip}};

    say hex2ip($hex_ip),
        ' -> ', hex2mac($hex_mac),
        ' (', format_time($mtime), ')';
 }
