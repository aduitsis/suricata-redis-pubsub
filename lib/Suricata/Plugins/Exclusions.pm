package Suricata::Plugins::Exclusions;
use v5.20;
use autodie;
use Try::Tiny;
use FindBin qw($Bin);


my $filename = "$Bin/../etc/exclude_ids.txt";
my @exclude_ids;
try {
	open my $exclusions,'<',$filename;
	chomp( @exclude_ids = grep { $_ !~ /^\s*#/ } ( <$exclusions> ) );
	close $exclusions;
}
catch {
	say $_
};
	

sub plugin_function {
	my $class = shift // die 'incorrect call';
	my $e = shift // die 'missing argument';

	# say STDERR $e->{ alert }->{ signature_id };
	# say STDERR join(',',@exclude_ids);
	if ( grep { $e->{ alert }->{ signature_id } == $_ } @exclude_ids ) {
		return { command => 'ignore' , message => 'excluding id '.$e->{ alert }->{ signature_id } }
	}
	else {
		return { command => 'noop' }
	}
}

1;
