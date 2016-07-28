#!/usr/bin/perl -w

use v5.20;
use warnings;
use strict;
use AnyEvent::Socket;
use Data::Dumper;
use Fatal qw(open close);
use FindBin qw($Bin);
use Getopt::Long;
use IO::Handle;
use JSON;
use AnyEvent::Redis;
use List::Util qw(any);
use FindBin qw($Bin);
use lib "$Bin/../lib";
use IPv6::Address;
use Data::Printer;
use Log::Log4perl;
use POSIX;

select STDOUT; $| = 1;

for my $lib (@INC) {
	my $logger_file = $lib.'/subscriber.logger';
	if (-f $logger_file) {
		Log::Log4perl->init($logger_file);
	}
}
my $logger = Log::Log4perl->get_logger;


GetOptions(
	'debug|d'		=> \my $DEBUG,
	'redis_host|r=s'	=> \my $redis_host,
	'redis_port|p=i'	=> \( my $redis_port = 6379 ),
	'nodrop'		=> \( my $no_drop ),
	'user|u=s'		=> \( my $run_as ),
	'tick|t=i'		=> \( my $tick = 10 ),
	'dest=s'		=> \( my $global_destination = 'self' ),
	'help|h|?'		=> \( my $help ),
	'severity-thres=i'	=> \( my $severity_threshold = 1 ),
	'exclude-sig=s@'	=> \( my $exclude_sigs ),
	'exclude-source=s@'	=> \( my $exclude_sources ),
	'exclude-destination=s@'=> \( my $exclude_destinations ),
	'exclude-dest-port=i@'	=> \( my $exclude_dest_ports ),
	'exclude-src-port=i@'	=> \( my $exclude_src_ports ),
	'duration=i'		=> \( my $duration = 60 ),
	'channel=s'		=> \( my $channel = 'suricata' ),
);

## pod2usage(-verbose=>2) if $help;

# now drop privileges https://gist.github.com/tommybutler/6944027
if( $run_as ) {
	my ( $uid, $gid ) = ( getpwnam $run_as )[ 2, 3 ];
	die $! unless $uid && $gid;
	if ( $> == 0 ) {
		POSIX::setgid( $gid ); # GID must be set before UID!
		POSIX::setuid( $uid );
	}
	else {
		die "Running as $> and cannot switch to nobody";
	}
}

$redis_host // die 'please supply the redis server with the --redis_host option';

my $quit_program = AnyEvent->condvar;

$SIG{PIPE} = sub {
	$logger->info("pipe broke");
	$quit_program->send;
};
# for some reason the above works while the
# following doesn't. 
#my $sigpipe = AnyEvent->signal (
#	signal => 'PIPE',
#	cb => sub {
#		$quit_program->send;
#		$logger->info("exiting...");
#		exit;
#	}
#);

my @excluded_sources = map { IPv4Subnet->new( $_ ) } @{ $exclude_sources } ;
my @excluded_destinations = map { IPv4Subnet->new( $_ ) } @{ $exclude_destinations } ;

my %ips;

$logger->info("Subscriber pid $$ starting");



my $redis = AnyEvent::Redis->new(
	host => $redis_host,
	port => $redis_port,
	encoding => 'utf8',
	on_error => sub { warn @_ },
	on_cleanup => sub { warn "Connection closed: @_" },
);

my $cv = $redis->subscribe($channel, sub {
	my ( $json, $channel ) = @_;
	my $message = decode_json( $json );	
	$logger->debug('new message:'.join(' ',map { $_.'='.$message->{event}->{$_} } sort keys %{$message->{event}} ));
	my $ip = $message->{ event }->{ src_ip };
	if( $message->{event}->{alert}->{severity} > $severity_threshold ) {
		$logger->debug("event excluded due to severity");
	}
	elsif( any { $_ eq $message->{event}->{alert}->{signature_id} } @{$exclude_sigs} ) {
		$logger->debug("event excluded due to signature");
	}
	elsif( any { $_->contains( $message->{event}->{src_ip} ) } @excluded_sources ) {
		$logger->debug( "event excluded due to source IP");
	}
	elsif( any { $_->contains( $message->{event}->{dest_ip} ) } @excluded_destinations ) {
		$logger->debug( "event excluded due to destination IP");
	}
	elsif( any { $message->{ event }->{ dest_port } == $_ } @{$exclude_dest_ports} ) {
		$logger->debug( "event excluded due to dest port");
	}
	elsif( any { $message->{ event }->{ src_port } == $_ } @{$exclude_src_ports} ) {
		$logger->debug( "event excluded due to src port");
	}
	else {
		$logger->info(join(' ',
			$message->{event}->{proto},
			$message->{event}->{src_ip}.':'.$message->{event}->{src_port},
			$message->{event}->{dest_ip}.':'.$message->{event}->{dest_port},
			$message->{event}->{alert}->{category}.' '.$message->{event}->{alert}->{signature}.' '.$message->{event}->{alert}->{signature_id},
		));
		# announce route 1.2.3.4/32 next-hop self
		my $str = "announce route $ip/32 next-hop $global_destination";
		$logger->info($str);
		say $str;
		# ($actual_channel is provided for pattern subscriptions.)
		$ips{ $ip } = $duration;
	}
});

my $w = AnyEvent->timer (after => 0, interval => $tick, cb => sub {
	$logger->trace( 'tick');
	for(keys %ips) {
		$ips{ $_ } -= $tick;
		if ($ips{ $_ }<=0) {
			my $str = "withdraw route $_/32 next-hop $global_destination";
			$logger->info($str);
			say $str;
			delete $ips{ $_ };
		}
		$DEBUG && say STDERR Dumper(\%ips)
	}
});


$quit_program->recv;

$logger->info('Told to exit, possibly due to sigpipe...bye!');

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

