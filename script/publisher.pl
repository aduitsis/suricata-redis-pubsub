#!/usr/local/bin/perl

use v5.20;
use warnings;
use strict;
use Data::Dumper;
use Fatal qw(open close);
use FindBin qw($Bin);
use lib "$Bin/../lib";
use lib "$Bin/../local/lib/perl5";
use AnyEvent::Socket;
use Getopt::Long;
use Pod::Usage;
use IO::Handle;
use JSON;
use Redis;
use POSIX;
use Sys::Hostname;
use Module::Find;

my @found = usesub Suricata::Plugins;

say "Found modules: ".join(',',@found);

GetOptions(
	'debug|d'	=> \my $DEBUG,
	'redis|r=s'	=> \my $redis_str,
	'sock|s=s'	=> \( my $sock = '/var/run/suricata.sock' ),
	'user|u=s'	=> \( my $run_as = 'nobody' ),
	'channel=s'	=> \( my $channel = 'suricata' ),
	'logstash'	=> \( my $logstash ),
	'help|h|?'	=> \( my $help ),
);

## pod2usage(-verbose=>2) if $help;

$redis_str // die 'please supply the redis server with the --redis option';
($redis_str !~ /:\d+$/ ) and ( $redis_str .= ':6379' );

my $quit_program = AnyEvent->condvar;

my $guard = tcp_server 'unix/', $sock , \&control_handler;

# now drop privileges https://gist.github.com/tommybutler/6944027
my ( $uid, $gid ) = ( getpwnam $run_as )[ 2, 3 ];
die $! unless $uid && $gid;
if ( $> == 0 ) {
	POSIX::setgid( $gid ); # GID must be set before UID!
	POSIX::setuid( $uid );
}
else {
	die "Running as $> and cannot switch to nobody";
}

my %watchers;

my $redis = Redis->new( server => $redis_str );

sub control_handler {
        my ($fh) = @_;
        binmode( $fh, ":unix" );
        ### say { $fh } "Hello, ready to accept commands";
        say STDERR "new connection from $fh";
        my $io_watcher = AnyEvent->io (
                fh      => $fh,
                poll    => 'r',
                cb      => sub {

                        ### WARNING!!! Messing with $_ can kill the entire event loop
                        ### use local $_ before doing any stunts like reassigning $_
                        ### for-loops are smart enough to localize $_ 

                        my $input = <$fh> // do {
				delete $watchers{ $fh };
				say STDERR "client closed the connection";
                                return
                        };
			chomp $input;
			my $d  = decode_json $input;
			#say STDERR Dumper($d);
			exists $d->{ src_ip } or return;
			exists $d->{ dest_ip } or return;
			say $d->{ src_ip } . ' --> '. $d->{ dest_ip } . '  ' . $d->{ alert }->{ signature } . ' ' . $d->{ alert }->{ signature_id } . ' (sev:' . $d->{ alert }->{ severity } .')';

			# evaluate modules
			for my $module (@found) {
				my $ret = $module->plugin_function( $d );
				# say STDERR join(' ' , map( { "$_ = ".$ret->{$_} } keys %{$ret} ));
				if( ( exists( $ret->{ command } ) ) && ( $ret->{ command } eq 'ignore' ) ) {
					say $ret->{ message } if exists($ret->{ message });
					#say STDERR "Skipping because $module said so";
					return
				}
			}

			#$redis->set( 'suricata:'.$d->{ src_ip } => $d->{ src_ip } , EX => 60 );
			my $message = {
				version		=> 1,
				date		=> time,
				id		=> 'suricata publisher',
				host		=> hostname,
				event		=> $d,
			};
			$redis->publish( $channel => encode_json( $message ) );

			if( $logstash ) {
				# logstash flat JSON, suitable for logstash redis subscribers
				if( exists $d->{alert} ) {
					# copy everything from the alert level to the top level
					$d->{ $_ } = $d->{alert}->{$_} for keys %{$d->{alert}};
					# and delete the nested field
					delete $d->{alert};
					$d->{host} = hostname;	
					# also add a [@metadata][time] field, so 
					# that logstash may adjust its @timestamp
					# suricata's timestamp format is just fine for logstash
					$d->{'@metadata'}->{time} = $d->{timestamp};
				}
				$redis->publish( "logstash-$channel" => encode_json( $d ) );
			}
		} 
	);
	$watchers{ $fh } = { fh => $fh , aio => $io_watcher } ;
}

$quit_program->recv;



# $VAR1 = {
#           'timestamp' => '2016-06-08T22:29:16.250407+0300',
#           'dest_port' => 53,
#           'flow_id' => '35430576640',
#           'vlan' => ,
#           'src_ip' => '',
#           'alert' => {
#                        'signature_id' => 2013357,
#                        'rev' => 1,
#                        'gid' => 1,
#                        'action' => 'allowed',
#                        'category' => 'Web Application Attack',
#                        'signature' => 'ET CURRENT_EVENTS Wordpress possible Malicious DNS-Requests - wordpress.com.* ',
#                        'severity' => 1
#                      },
#           'dest_ip' => '',
#           'proto' => 'UDP',
#           'in_iface' => 'ix0',
#           'event_type' => 'alert',
#           'src_port' => 45417
#         };

