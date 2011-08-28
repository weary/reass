/*
 * Copyright 2011 Hylke Vellinga
 */


#include "tcp_reassembler.h"
#include "packet_listener.h"
#include "shared/misc.h"
#include <boost/static_assert.hpp>
#include "netinet/ip.h"
#include "netinet/ip6.h"
#include "netinet/tcp.h"

BOOST_STATIC_ASSERT(offsetof(sockaddr_in,sin_port) == offsetof(sockaddr_in6,sin6_port));
BOOST_STATIC_ASSERT(sizeof(ip_address_t) == sizeof(sockaddr_in6));

tcp_stream_t::tcp_stream_t(tcp_stream_t *&free_head) :
	free_list_member_t<tcp_stream_t>(free_head)
{
}

tcp_stream_t::~tcp_stream_t()
{
}

void tcp_stream_t::init(packet_listener_t *listener, const packet_t *packet)
{
	d_listener = listener;
	int n = -1;
	const layer_t *tcplay = packet->layer(n);
	while (tcplay && tcplay->type != layer_tcp)
		tcplay = packet->layer(--n);
	if (!tcplay)
		throw format_exception("expected tcp layer");

	const layer_t *iplay = packet->layer(n);
	while (iplay && iplay->type != layer_ipv4 && iplay->type != layer_ipv6)
		iplay = packet->layer(--n);
	if (!iplay)
		throw format_exception("expected ip layer before tcp layer");

#ifdef DEBUG
	::memset(&d_src, 'X', sizeof(d_src));
	::memset(&d_dst, 'X', sizeof(d_dst));
#endif
	const tcphdr &hdr1 = reinterpret_cast<const tcphdr &>(*tcplay->begin);
	if (iplay->type == layer_ipv4)
	{
		const iphdr &hdr2 = reinterpret_cast<const iphdr &>(*iplay->begin);
		d_src.v4.sin_family = AF_INET;
		d_src.v4.sin_port = hdr1.source;
		d_src.v4.sin_addr.s_addr = hdr2.saddr;

		d_dst.v4.sin_family = AF_INET;
		d_dst.v4.sin_port = hdr1.dest;
		d_dst.v4.sin_addr.s_addr = hdr2.daddr;
	}
	else
	{
		const ip6_hdr &hdr2 = reinterpret_cast<const ip6_hdr &>(*iplay->begin);
		assert(iplay->type == layer_ipv6);
		d_src.v6.sin6_family = AF_INET6;
		d_src.v6.sin6_port = hdr1.source;
		d_src.v6.sin6_addr = hdr2.ip6_src;
		d_src.v6.sin6_flowinfo = 0;
		d_src.v6.sin6_scope_id = 0;

		d_dst.v6.sin6_family = AF_INET6;
		d_dst.v6.sin6_port = hdr1.dest;
		d_dst.v6.sin6_addr = hdr2.ip6_dst;
		d_dst.v6.sin6_flowinfo = 0;
		d_dst.v6.sin6_scope_id = 0;
	}
}

void tcp_stream_t::add(packet_t *packet)
{
	d_listener->accept_tcp(packet, this);
}

void tcp_stream_t::print(std::ostream &os) const
{
	os << d_src << " -> " << d_dst;
}

std::ostream &operator <<(std::ostream &os, const tcp_stream_t &s)
{
	s.print(os);
	return os;
}

tcp_reassembler_t::tcp_reassembler_t(packet_listener_t *listener) :
	d_listener(listener)
{
}

tcp_reassembler_t::~tcp_reassembler_t()
{
}

#include <iostream>
tcp_stream_t *tcp_reassembler_t::find_stream(packet_t *packet)
{
	tcp_stream_t *r = claim();
	auto_release_t<tcp_stream_t> releaser(r);

	r->init(d_listener, packet);
	stream_set_t::iterator i = d_streams.find(r);
	if (i == d_streams.end())
	{
		std::cout << *r << " (NEW)\n";
		d_streams.insert(r);
		releaser.do_not_release();
		return r;
	}
	else
	{
		std::cout << *r << " (EXISTING)\n";
		return *i;
	}
}

void tcp_reassembler_t::process(packet_t *packet)
{
	tcp_stream_t *r = find_stream(packet);
	r->add(packet);
}

