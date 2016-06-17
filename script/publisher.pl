#!/usr/bin/env perl

use v5.20;
use warnings;
use strict;
use AnyEvent::Socket;
use Data::Dumper;
use Fatal qw(open close);
use FindBin qw($Bin);
use Getopt::Long;
use Pod::Usage;
use IO::Handle;
use JSON;
use Redis;
use POSIX;
use Sys::Hostname;

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
my ( $uid, $gid ) = ( getpwnam 'nobody' )[ 2, 3 ];
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
			# say STDERR Dumper($d);
			say $d->{ src_ip } . ' '. $d->{ alert }->{ signature } . ' ' . $d->{ alert }->{ signature_id };
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
					$d->{ $_ } = $d->{alert}->{$_} for keys %{$d->{alert}};
					delete $d->{alert};
					$d->{host} = hostname;	
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

