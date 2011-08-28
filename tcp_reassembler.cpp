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

std::ostream &operator <<(std::ostream &os, const seq_nr_t &s)
{
	char buf[5];
	sprintf(buf, "%04x", s.d_val);
	os << buf;
	return os;
}

static bool operator >(const seq_nr_t &l, const seq_nr_t &r)
{
	return r < l;
}

#if 0
static bool operator ==(const seq_nr_t &l, const seq_nr_t &r)
{
	return l.d_val == r.d_val;
}
#endif

static bool operator <=(const seq_nr_t &l, const seq_nr_t &r)
{
	int32_t diff = l.d_val - r.d_val;
	return diff <= 0;
}


tcp_stream_t::tcp_stream_t(tcp_stream_t *&free_head) :
	free_list_member_t<tcp_stream_t>(free_head)
{
}

tcp_stream_t::~tcp_stream_t()
{
}

void tcp_stream_t::init(packet_listener_t *listener)
{
	d_listener = listener;
	d_trust_seq = false;
}

static const layer_t *find_tcp_layer(const packet_t *packet)
{
	int n = -1;
	const layer_t *tcplay = packet->layer(n);
	while (tcplay && tcplay->type != layer_tcp)
		tcplay = packet->layer(--n);
	return tcplay;
}

void tcp_stream_t::set_src_dst_from_packet(const packet_t *packet)
{
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
	const layer_t *tcplay = find_tcp_layer(packet);
	assert(tcplay);

	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->begin);

	seq_nr_t seq(htonl(hdr.seq));

	if (!d_trust_seq) // check if we already have a starting packet
	{
		if (hdr.syn) // syn-packets signify a first packet
		{
			d_trust_seq = true;
			d_next_seq = seq;
		}
		else
		{
			seq_nr_t seq = htonl(hdr.seq);
			if (d_delayed.empty())
				d_next_seq = seq; // first guess at correct seq
			else
			{
				if (seq <= d_next_seq) // wait until sequence numbers are increasing
					d_next_seq = seq;
				else
				{
					d_trust_seq = true;
					check_delayed();
				}
			}
		}
	}

	if (d_trust_seq)
	{
		if (seq <= d_next_seq)
			accept_packet(packet, tcplay);
		else
			d_delayed.insert(delayed_t::value_type(seq, packet));
	}
	else
		d_delayed.insert(delayed_t::value_type(seq, packet));

	if (d_delayed.size() > 16)
	{
		d_trust_seq = true; // if this wasn't set yet, it was seriously screwed up
		check_delayed(true);
	}
}

void tcp_stream_t::accept_packet(packet_t *packet, const layer_t *tcplay)
{
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->begin);
	layer_t *next = tcplay->next();

	size_t psize = 0;
	if (next) psize = next->size();
	assert(!next || (next->last_layer && next->type == layer_data)); // assume we are the last
	assert(!psize || !hdr.syn); // assume syn-packets will not have content. will break some day
	seq_nr_t seq = htonl(hdr.seq);
	int32_t packetloss = seq.d_val - d_next_seq.d_val;
	int32_t overlap = -packetloss;
	if (psize)
	{ // we have content
		if (overlap > 0)
		{
			if ((uint32_t)overlap > psize)
				packet->add_layer(layer_data, next->end, next->end);
			else
				packet->add_layer(layer_data, next->begin + overlap, next->end);
		}
		seq.d_val += psize;
	}
	else
	{ // no content
		if (hdr.syn) ++seq.d_val;
	}
	if (packetloss < 0) packetloss = 0;

	if (seq > d_next_seq)
		d_next_seq = seq;

	d_listener->accept_tcp(packet, packetloss, this);

	check_delayed();
}

void tcp_stream_t::check_delayed(bool force /* force at least one packet out */)
{
	if(d_delayed.empty())
		return;

	delayed_t::iterator i = d_delayed.begin();
	seq_nr_t seq = i->first;
	if (force || seq <= d_next_seq)
	{
		packet_t *packet = i->second;
		d_delayed.erase(i);
		const layer_t *tcplay = find_tcp_layer(packet);
		accept_packet(packet, tcplay);
	}
}

void tcp_stream_t::flush()
{
	while (!d_delayed.empty())
		check_delayed(true);
}

void tcp_stream_t::release()
{
	flush();
#ifdef DEBUG
	::memset(&d_src, 'X', sizeof(d_src));
	::memset(&d_dst, 'X', sizeof(d_dst));
#endif
	free_list_member_t<tcp_stream_t>::release();
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
	for(stream_set_t::iterator i = d_streams.begin(); i!= d_streams.end(); ++i)
	{
		tcp_stream_t *stream = const_cast<tcp_stream_t *>(*i);
		stream->release();
	}
}

#include <iostream>
tcp_stream_t *tcp_reassembler_t::find_stream(packet_t *packet)
{
	tcp_stream_t *r = claim();
	auto_release_t<tcp_stream_t> releaser(r);

	r->set_src_dst_from_packet(packet);
	stream_set_t::iterator i = d_streams.find(r);

	// FIXME: check for port-reuse here

	if (i == d_streams.end())
	{
		// FIXME: check for partner here

		r->init(d_listener);
		d_streams.insert(r);
		releaser.do_not_release();
		return r;
	}
	else
		return *i;
}

void tcp_reassembler_t::process(packet_t *packet)
{
	tcp_stream_t *r = find_stream(packet);
	r->add(packet);
}

