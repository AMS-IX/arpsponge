#!perl

use Test::More;

if (! eval { require Test::Perl::Critic }) {
    Test::More::plan(
        skip_all => "Test::Perl::Critic required for testing PBP compliance"
    );
}
elsif (exists $::ENV{'CRITIC'}
    && $::ENV{'CRITIC'} =~ /^(y|yes|true|0*[1-9])/i) {

    Test::Perl::Critic::all_critic_ok();
}
else {
    Test::More::plan(
        skip_all => "Set CRITIC=1 to run"
    );
}
