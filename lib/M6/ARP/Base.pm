# @(#)$Id$
#===============================================================================
#
#       Module:  M6::ARP::Base
#         File:  M6/ARP/Base.pm
#
#  Description:  Base class for all M6::ARP objects.
#
#       Author:  Steven Bakker (SB), <steven.bakker@ams-ix.net>
#      Created:  2010-10-07
#
#   Copyright (c) 2010 AMS-IX B.V.; All rights reserved.
#
#   This module is free software; you can redistribute it and/or
#   modify it under the same terms as Perl itself. See perldoc perlartistic.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
#===============================================================================

package M6::ARP::Base;

use strict;
#use warnings;
our $VERSION = '1.00';

use Scalar::Util    qw( reftype );
use Carp            qw( confess );

our %attr_names = ();

############################################################################
# Usage         : $obj->attr_names(), CLASS->attr_names()
# Purpose       : returns the valid (constructor) attributes for the class
# Returns       : a REFerence to a hash mapping attribute names to "1".
# Parameters    : none
# Throws        : no exceptions
# Comments      : Takes the class-wide %attr_names from $obj or CLASS.
sub attr_names {
    my $class = ref $_[0] || $_[0];
    return eval q(\%).$class.q(::attr_names);
}

############################################################################
# Usage         : $obj->parent_attr_names(), CLASS->parent_attr_names()
# Purpose       : returns the valid (constructor) attributes for the parents
#                 of $obj or CLASS.
# Returns       : a hash mapping attribute names to "1".
# Parameters    : an optional list of additional valid attribute names.
# Throws        : no exceptions
# Comments      : Similar to attr_names(), but this is typically used in the
#                 class's code to construct the %attr_names:
#
#                   package Foo;
#                   use base qw( Bar );
#                   our %attr_names = ( foo=>1, Foo->parent_attr_names );
#
sub parent_attr_names {
    my $self = shift @_;
    my $class = ref $self || $self;
    return (
        ( map { eval q(%).$_.q(::attr_names) } eval q(@).$class.q(::ISA) ),
        ( map { $_ => 1 } @_ )
    );
}

############################################################################
# Usage         : CLASS->new()
# Purpose       : constructor
# Returns       : a blessed HASH reference
# Parameters    : NAME=>VALUE pairs for initial attributes
# Throws        : exception in case of invalid attributes
sub new {
    my ($type, @args) = @_;

    my $self = $type->parse_named_args(\@args, $type->attr_names);
    #my $self = $type->parse_named_args(\@args);
    return if ! $self;

    bless $self, $type;
    return $self->init();
}

sub init { return shift }

# 1: $obj->parse_named_args();
# 2: $obj->parse_named_args( undef );
# 3: $obj->parse_named_args( [ undef ] );
# 5: $obj->parse_named_args( [ key => val, ... ] );
# 4: $obj->parse_named_args( [ { key => val, ... } ] );
# 6: $obj->parse_named_args( { key => val, ... } );
#
# Optional parameter "$valid_ref" is either { key => 1, ... } or [ key, ... ]
#
sub parse_named_args {
    my $self = shift;

    return {} if @_ == 0;                       # 1

    my $args_ref = shift;

    if (! defined $args_ref) {
        return {};                              # 2
    }
    elsif (reftype $args_ref eq 'HASH') {
        1;                                      # 6
    }
    elsif (reftype $args_ref eq 'ARRAY') {
        if (!defined $args_ref->[0]) {
            return {};                          # 3
        }
        elsif (@$args_ref % 2 == 0) {
            $args_ref = { @$args_ref };         # 4
        }
        elsif (@$args_ref == 1 && reftype $args_ref->[0] eq 'HASH') {
            $args_ref = $args_ref->[0];         # 5
        }
        else {
            confess("_named_args: Odd number of arguments:\n",
                    "   ", join(", ", @$args_ref), "\n");
        }
    }
    else {
        confess( qq{_named_args: parameter #0 ("$args_ref") not a HASH or},
                 qq{ ARRAY ref: $args_ref\n} );
    }

    my %attr;

    while (my ($attr_name, $attr_value) = each %$args_ref) {
        $attr_name =~ s/^-+//g;
        $attr{lc $attr_name} = $attr_value;
    }

    return \%attr if @_ == 0;

    if (my $valid_ref = shift @_) {
        if (reftype $valid_ref eq 'ARRAY') {
            $valid_ref = { map { $_ => 1 } @$valid_ref };
        }
        for my $attr_name (keys %attr) {
            if ( ! $valid_ref->{$attr_name} ) {
                confess(qq{\nparse_named_args: Bad attribute "$attr_name"; },
                    qq{valid: }, join(", ", keys %$valid_ref),"\n");
            }
        }
    }
    return \%attr;
}

sub _define_accessor {
    my $class = shift;
    my ($name, $key) = ref $_[0] ? @{$_[0]} : ($_[0], $_[0]);

    my $sub = "sub ${class}::$name {\n"
            . " if (\@_ < 2) { return \$_[0]->{'$key'} }\n"
            . " else {\n"
            . "  my \$s = shift;\n"
            . "  \$->{'$key'} = shift;\n"
            . "  return \$s;\n"
            . " }\n"
            . "}\n"
            . ";1\n"
          ;

    eval $sub;

    if ($@) {
        my $lno = 1;
        my @sub = split("\n", $sub);
           @sub = map { sprintf("%3d\t$_\n", $lno++) } @sub;
        print STDERR "----\n", @sub, "----\n";
        confess($@);
    }
    return 1;
}

sub mk_accessors {
    my $class = shift;
    foreach (@_) {
        $class->_define_accessor($_);
    }
}

1;

__END__

=pod

=head1 NAME

M6::ARP::Base - base class for all M6::ARP objects

=head1 SYNOPSIS

 package M6::ARP::SomeObj;

 use base qw( M6::ARP::Base );

 our %attr_names = __PACKAGE__->parent_attr_names('banana');
                                          # (banana=>1, monkey=>1)

 __PACKAGE__->mk_accessors('banana', ['banana_alias' => 'banana']);

 ...

 package main;

 $obj = new M6::ARP::SomeObj;
 %attr_names = $obj->attr_names(); # ('monkey'=>1, 'banana'=>1)

 my $monkey = $obj->monkey();
 my $banana = $obj->banana();
 my $banana = $obj->banana_alias();

=head1 DESCRIPTION

C<M6::ARP::Base> provides a base class for all M6::ARP
objects. It only defines common class methods and does not
look directly at an object's instance data.

=head1 CONSTRUCTORS

=over

=item X<new (constructor)> B<new> ( I<ATTR> =E<gt> I<VAL>, ... )

Simple constructor for a hash-based object. Optional initial attributes
(key/value pairs for the hash) can be specified, and the constructor
will make sure that they comply with the target class'
L<attr_names()|/attr_names (method)>.

Returns a simple HASH ref, blessed into the appropriate
(descendant) package.

=back

=head1 METHODS

=over

=item X<attr_names (method)>B<attr_names>

Returns a HASH reference mapping valid attribute names for this class to
"1".  Can be called as either a class method or an instance method
(but not as a plain function).

It assumes that the descendant has defined an I<%attr_names> variable in
its package scope and will use that to return the list of names.

=item X<parent_attr_names (method)>B<parent_attr_names> ( [I<ATTRLIST>] )

Returns a HASH composed of the contents of the
L<attr_names (method)|/attr_names> hashes of all parent classes in this
class's C<@ISA>.

This is typically only used in a package's set-up code:

    package Bar;
    use base qw( M6::ARP::Base );
    our %attr_names = ('bar' => 1, Bar->parent_attr_names); # bar=>1

    package Foo;
    use base qw( Bar );
    our %attr_names = ('foo' => 1, Foo->parent_attr_names); # foo=>1, bar=>1

To shorten the above, it is possible to provide the additional
attribute names in the I<ATTRLIST> argument:

    package Bar;
    use base qw( M6::ARP::Base );
    our %attr_names = Bar->parent_attr_names('bar'); # bar=>1

    package Foo;
    use base qw( Bar );
    our %attr_names = Foo->parent_attr_names('foo'); # foo=>1, bar=>1

=item X<parse_named_args (method)>
B<parse_named_args> ( I<HASH_REF> [, I<VALID_REF> ] )

=item B<parse_named_args> ( I<LIST_REF> [, I<VALID_REF> ] )

Normalises the keys in I<HASH_REF> and stores the results in a new hash.
If a I<LIST_REF> is given instead, it first coerces it into a hash, then
normalises it.

Key normalisation consists of translating it to lowercase, removing all
spaces and all leading hyphen (C<->, C<-->) characters.

If I<VALID_REF> is given (either as an ARRAYREF or a HASHREF), then
(normalised) parameter names are checked against the attribute names
specified there (the elements in "@{I<VALID_REF>}" or the keys in
"%{I<VALID_REF>}", resp.).

If an invalid key is encountered, the function calls
L<Carp::confess()|Carp/confess>.

Can be called as a function or (class) method.

    $args_ref = $obj->parse_named_args( \%args, \@valid );
    $args_ref = CLASS->parse_named_args( \@_, \%valid );

The function returns a reference to the new (normalised) hash.

Example:

    package Something;
    use base qw( M6::ARP::Base );

    sub do_something {
        my $self = shift;

        print "args:", (map { qq{ "$_"}  } @_), "\n";

        my $args = $self->parse_named_args( \@_, [qw( foo bar )]);

        while ( my ($k, $v) = each %$args ) {
            print qq{"$k" => "$v"\n};
        }
    }

    Something->do_something(--FOO => 'my foo', -bAr => 'my BAR');

Prints:

    args: "--FOO" "my foo" "-bAr" "my BAR"
    "bar" => "my BAR"
    "foo" => "my foo"

=back

=head1 SEE ALSO

L<M6::ARP::Sponge(3)|M6::ARP::Sponge>,
L<M6::ARP::Queue(3)|M6::ARP::Queue>.

=head1 AUTHOR

Steven Bakker E<lt>steven.bakker@ams-ix.netE<gt>, AMS-IX B.V.; 2010.

=cut
