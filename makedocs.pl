use strict;

my $str = '';
my $regex = qr/(<[^\/].*?>.*?<\/.*?>\n?)|(<\/div>)|(<\/p>)/msp;
my $subst = '';


local $/=undef;
open FILE, '<', 'README.md' or die "Can't open file $!";
my $file_content = <FILE>;
close FILE;
#print "Source: $file_content\n";
my $result = $file_content =~ s/$regex//rg;

my $regex2 = qr/\n[ \n]{3,}\n/msp;
$result = $result =~ s/$regex2/\n\n/rg;

#print "The result of the substitution is: $result\n";
print "$result\n";
