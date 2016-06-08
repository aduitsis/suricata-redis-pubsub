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

GetOptions(
	'debug|d'		=> \my $DEBUG,
	'redis_host|r=s'	=> \my $redis_host,
	'redis_port|p=i'	=> \( my $redis_port = 6379 ),
	'user|u=s'		=> \( my $run_as = 'nobody' ),
	'tick|t=i'		=> \( my $tick = 10 ),
	'help|h|?'		=> \( my $help ),
);

## pod2usage(-verbose=>2) if $help;

$redis_host // die 'please supply the redis server with the --redis_host option';


my $quit_program = AnyEvent->condvar;

my %ips;

my $redis = AnyEvent::Redis->new(
	host => $redis_host,
	port => $redis_port,
	encoding => 'utf8',
	on_error => sub { warn @_ },
	on_cleanup => sub { warn "Connection closed: @_" },
);

my $cv = $redis->subscribe("suricata", sub {
	my ( $message, $channel ) = @_;
	say '+ '.$message;
	# ($actual_channel is provided for pattern subscriptions.)
	$ips{ $message } = 60;
});

my $w = AnyEvent->timer (after => 0, interval => $tick, cb => sub {
	$DEBUG && say STDERR 'tick';
	for(keys %ips) {
		$ips{ $_ } -= $tick;
		if ($ips{ $_ }<=0) {
			say '- '. $_;
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

