#!/usr/bin/perl
# Compare two signatures and print them out side by side with colours for easy comparison
# Eval's objects/code from files... very dangerous
use strict;
use warnings;

die "Usage $0 file1 file2\n" if ($#ARGV != 1);
my $obj1;
my $obj2;
{
  local $/;
  open (my $fh, $ARGV[0]);
  my $code = <$fh>;
  #my $VAR1 = eval(<$fh>);
  $obj1 = eval $code;
  open ($fh, $ARGV[1]);
  $code = <$fh>;
  $obj2 = eval $code;
};
#print "$obj1\n";
print "$obj1->{'target'} - ".join(" ",keys(%{ $obj1->{'webserver'} })) ."\n";
# compare loop goes here....
my @sigarr1 = ( $obj1->{'signature'} =~ /../g );
my @sigarr2 = ( $obj2->{'signature'} =~ /../g );
my $g = "\e[30m\e[K";
my $r = "\e[31m\e[K";
my $c;
my $sig1;
my $sig2;
for (my $x = 0; $x < $#sigarr1; $x++) {
  if ( $sigarr1[$x] eq $sigarr2[$x] ) {
    $c = $g;
  } else {
    $c = $r;
  }
  $sig1 .= $c . $sigarr1[$x];
  $sig2 .= $c . $sigarr2[$x];
}
print "$sig1\n";
print "$sig2\e[m\e[K\n";
print "$obj2->{'target'} - ".join(" ",keys(%{ $obj2->{'webserver'} })) ."\n";
