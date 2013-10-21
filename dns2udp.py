#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.application import service, internet
from twisted.internet import reactor, defer, protocol
from twisted.names import client, server, common, dns
from twisted.python import log as twisted_log

import itertools as it, operator as op, functools as ft
from contextlib import contextmanager
from collections import deque, namedtuple
import os, sys, re, socket, logging


class UDPBase(protocol.DatagramProtocol):
	noisy = False


Address = namedtuple('Address', 'ip n port af')

class UDPLink(UDPBase):

	def __init__(self, addr_dst, pkt_buffer_len=1000):
		ip, port = addr_dst
		af = socket.AF_INET if ':' not in ip else socket.AF_INET6
		self.addr_dst = Address(ip, socket.inet_pton(af, ip), int(port), af)
		self.recv_queue = deque(maxlen=pkt_buffer_len)
		self.log = logging.getLogger('dns2udp.link')

	def datagramReceived(self, msg, addr):
		ip, port = addr
		try:
			assert port == self.addr_dst.port
			if ip != self.addr_dst.ip:
				assert socket.inet_pton(self.addr_dst.af, ip) == self.addr_dst.n
		except (socket.error, AssertionError):
			self.log.info('Discarded msg from non-dst address: %s', addr)
			return
		self.log.debug('Received msg: %r', msg)
		self.recv_queue.append(msg)

	def get(self):
		try: return self.recv_queue.popleft()
		except IndexError: pass

	def send(self, msg):
		try: self.transport.write(msg, (self.addr_dst.ip, self.addr_dst.port))
		except (OverflowError, socket.error, socket.gaierror) as err:
			self.log.info('Failed to send message to addr_dst: %s', err)


class UDPDNSEncoder(UDPBase):

	def __init__(self, ns_addr):
		self.ns = client.createResolver(servers=[ns_addr])
		self.log = logging.getLogger('dns2udp.encoder')

	@defer.inlineCallbacks
	def datagramReceived(self, msg, addr):
		ans, auth, add = yield self.ns.lookupText(msg)
		replies = filter(None, (''.join(reply.payload.data) for reply in ans))
		for reply in replies:
			try: self.transport.write(reply, addr)
			except (OverflowError, socket.error, socket.gaierror) as err:
				self.log.info('Failed to send reply: %s', err)
		self.log.debug('Sent: %r, recv: %r', msg, replies)


class UDPDNSDecoder(common.ResolverBase):

	def __init__(self, addr_dst, out_bind=None):
		self.link = UDPLink(addr_dst)
		if out_bind:
			interface, port = out_bind
			reactor.listenUDP(port, self.link, interface)
		else: reactor.listenUDP(0, self.link)
		self.log = logging.getLogger('dns2udp.decoder')

	def query(self, query, timeout=None):
		if query.type != dns.TXT:
			self.log.info('Unhandled DNS query class/type: %s/%s', query.type)
		msg_out, msg_in = query.name.name, (self.link.get() or '')
		self.link.send(msg_out)
		self.log.debug('Sent: %r, recv: %r', msg_out, msg_in)
		return [dns.RRHeader( msg_out, type=dns.TXT,
			payload=dns.Record_TXT(msg_in), auth=True )], list(), list()



def endpoint_parse( spec, mandatory_port=False,
		_re=re.compile(r'^(\[([^\]]+)\]|[\d.]+)(:(?P<port>\d+))?$') ):
	match = _re.search(spec)
	if not match: raise ValueError(spec)
	ip, port = match.group(2) or match.group(1), match.group('port')
	if port: port = int(port)
	elif mandatory_port: raise ValueError(spec)
	return ip, port


def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Tool to pipe UDP traffic through dns queries.')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')

	cmds = parser.add_subparsers(
		title='Supported operations (have their own suboptions as well)')

	@contextmanager
	def subcommand(name, **kws):
		cmd = cmds.add_parser(name, **kws)
		cmd.set_defaults(call=name)
		yield cmd

	with subcommand( 'dns-server',
			help='Start DNS resolver that decodes TXT queries'
				' as UDP packets and sends them to destination IP/port.' ) as cmd:
		cmd.add_argument('dst', help='IP:PORT to send decoded UDP packets to.')
		cmd.add_argument('-i', '--ns-bind',
			metavar='IP[:PORT]', default='127.0.0.1:5353',
			help='IP/port to listen on for DNS queries (default: %(default)s).'
				' IPv6 address must be enclosed in square brackets, like this: [::]')
		cmd.add_argument('-s', '--out-bind', metavar='IP[:PORT]', default=None,
			help='Bind outgoing UDP packets to this IP/port. Same format as with --dns-bind.')

	with subcommand( 'dns-client',
			help='Listen on UDP socket for traffic to encode into DNS TXT queries.' ) as cmd:
		cmd.add_argument('listen', help='Listen for UDP traffic on specified IP:PORT.')
		cmd.add_argument('ns_addr', help='IP[:PORT] of DNS server to send all queries to.')

	opts = parser.parse_args(argv or sys.argv[1:])

	twisted_log.defaultObserver.stop()
	twisted_log.PythonLoggingObserver().start()
	logging.basicConfig(level=logging.WARNING if not opts.debug else logging.DEBUG)
	log = logging.getLogger('dns2udp.core')

	if opts.call == 'dns-server':
		dst = endpoint_parse(opts.dst, mandatory_port=True)
		ns_ip, ns_port = endpoint_parse(opts.ns_bind)
		out_bind = opts.out_bind
		if out_bind: out_bind = endpoint_parse(opts.out_bind)
		proto = dns.DNSDatagramProtocol(
			server.DNSServerFactory(clients=[UDPDNSDecoder(dst, out_bind=out_bind)]) )
		reactor.listenUDP(ns_port, proto, interface=ns_ip)

	elif opts.call == 'dns-client':
		ip, port = endpoint_parse(opts.listen, mandatory_port=True)
		ns_ip, ns_port = endpoint_parse(opts.ns_addr)
		proto = UDPDNSEncoder((ns_ip, ns_port or 53))
		reactor.listenUDP(port, proto, interface=ip)

	else: parser.error('Unrecognized command: {}'.format(opts.call))

	log.debug('Starting server loop...')
	reactor.run()
	log.debug('Server stopped')


if __name__ == '__main__': sys.exit(main())
