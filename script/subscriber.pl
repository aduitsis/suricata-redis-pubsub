#!/usr/bin/env perl

use v5.14;

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

GetOptions(
	'debug|d'		=> \my $DEBUG,
	'redis_host|r=s'	=> \my $redis_host,
	'redis_port|p=i'	=> \( my $redis_port = 6379 ),
	'user|u=s'		=> \( my $run_as = 'nobody' ),
	'tick|t=i'		=> \( my $tick = 10 ),
	'dest=s'		=> \( my $global_destination = 'self' ),
	'help|h|?'		=> \( my $help ),
	'severity-thres=i'	=> \( my $severity_threshold = 1 ),
	'exclude-sig=s@'	=> \( my $exclude_sigs ),
	'exclude-source=s@'	=> \( my $exclude_sources ),
	'duration=i'		=> \( my $duration = 60 ),
	'channel=s'		=> \( my $channel = 'suricata' ),
);

## pod2usage(-verbose=>2) if $help;

$redis_host // die 'please supply the redis server with the --redis_host option';

my $quit_program = AnyEvent->condvar;

my @excluded_sources = map { IPv4Subnet->new( $_ ) } @{ $exclude_sources } ;

my %ips;

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
	$DEBUG && p $message;
	my $ip = $message->{ event }->{ src_ip };
	if( $message->{event}->{alert}->{severity} > $severity_threshold ) {
		$DEBUG && say STDERR "event excluded due to severity";
	}
	elsif( any { $_ eq $message->{event}->{alert}->{signature_id} } @{$exclude_sigs} ) {
		$DEBUG && say STDERR "event excluded due to signature";
	}
	elsif( any { $_->contains( $message->{event}->{src_ip} ) } @excluded_sources ) {
		$DEBUG && say STDERR "event excluded due to source IP"
	}
	else {
		say "announce route $ip/32 next-hop $global_destination";
		# ($actual_channel is provided for pattern subscriptions.)
		$ips{ $ip } = $duration;
	}
});

my $w = AnyEvent->timer (after => 0, interval => $tick, cb => sub {
	$DEBUG && say STDERR 'tick';
	for(keys %ips) {
		$ips{ $_ } -= $tick;
		if ($ips{ $_ }<=0) {
			$DEBUG && say STDERR '- '. $_;
			say "withdraw route $_/32 next-hop $global_destination";
			delete $ips{ $_ };
		}
		$DEBUG && say STDERR Dumper(\%ips)
	}
});


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

