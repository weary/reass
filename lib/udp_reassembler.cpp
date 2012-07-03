/*
 * Copyright 2011 Hylke Vellinga
 */


#include "udp_reassembler.h"
#include "packet_listener.h"
#include "shared/misc.h"
#include <boost/version.hpp>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

static_assert(BOOST_VERSION != 104800, "bug 6153 in boost::intrusive in boost 1.48 prevents compilation");  // see https://svn.boost.org/trac/boost/ticket/6153
static_assert(offsetof(sockaddr_in,sin_port) == offsetof(sockaddr_in6,sin6_port), "ipv4 and ipv6 port number alignment broken");
static_assert(sizeof(ip_address_t) == sizeof(sockaddr_in6), "structure size broken");


uint64_t udp_stream_t::timeout() const
{
	return d_highest_ts.tv_sec + 60;
}


udp_stream_t::udp_stream_t(udp_stream_t *&free_head) :
	common_t(free_head)
{
}

udp_stream_t::~udp_stream_t()
{
}

void udp_stream_t::init(packet_listener_t *listener)
{
	common_t::init(listener);
	d_highest_ts.tv_sec = 0; d_highest_ts.tv_usec = 0;
	d_direction = direction_unknown;
	assert(d_delayed.empty()); // leftover packets would give funny results :)
}

void udp_stream_t::set_src_dst_from_packet(const packet_t *packet, bool swap /* construct src/dst inverted stream */)
{
	const layer_t *udplay = find_top_nondata_layer(packet);
	if (!udplay || udplay->type() != layer_udp)
		throw format_exception("expected udp layer");

	const layer_t *iplay = packet->prev(udplay);
	while (iplay && iplay->type() != layer_ipv4 && iplay->type() != layer_ipv6)
		iplay = packet->prev(iplay);
	if (!iplay)
		throw format_exception("expected ip layer before udp layer");

	const udphdr &hdr1 = reinterpret_cast<const udphdr &>(*udplay->data());
	if (iplay->type() == layer_ipv4)
	{
		const iphdr &hdr2 = reinterpret_cast<const iphdr &>(*iplay->data());
		common_t::set_src_dst4(
				hdr2.saddr, hdr1.source,
				hdr2.daddr, hdr1.dest,
				swap);
	}
	else
	{
		const ip6_hdr &hdr2 = reinterpret_cast<const ip6_hdr &>(*iplay->data());
		assert(iplay->type() == layer_ipv6);
		common_t::set_src_dst6(
				hdr2.ip6_src, hdr1.source,
				hdr2.ip6_dst, hdr1.dest,
				swap);
	}
}

void udp_stream_t::found_partner(udp_stream_t *other)
{
	assert(other != this);
	if (other->is_partner_set())
		return; // too late. our partner gave up on us

	assert(!is_partner_set() && !other->is_partner_set());
	set_partner(other);
	other->set_partner(this);
	d_direction = direction_responder;
	other->d_direction = direction_initiator;
	if (other->have_delayed())
		other->replay_delayed();
	assert(!have_delayed());
}


// add a packet, will either queue it in d_delayed, or accept it
void udp_stream_t::add(packet_t *packet, const layer_t *udplay)
{
	assert(udplay);

	if (packet->ts() > d_highest_ts)
		d_highest_ts = packet->ts();

	if (is_partner_set()) // partner is also set if we gave up looking
		accept_packet(packet, udplay);
	else
		d_delayed.push_back(packet);

	// fallback, don't queue too much
	if (d_delayed.size() > MAX_DELAYED_PACKETS)
		flush(); // give up
}

// called when we decided this is the packet that should be sent out
void udp_stream_t::accept_packet(packet_t *packet, const layer_t *udplay)
{
	assert(d_direction != direction_unknown);

	listener()->accept_udp(packet, this);
}

// check if we can accept some packets given current sequencenumbers
void udp_stream_t::replay_delayed()
{
	assert(!d_delayed.empty());
	assert(is_partner_set());

	for(packet_t *packet: d_delayed)
	{
		const layer_t *udplay = find_top_nondata_layer(packet);
		assert(udplay && udplay->type() == layer_udp);
		accept_packet(packet, udplay);
	}
	d_delayed.clear();
}

// we gave up on stream. emit everything we have
void udp_stream_t::flush()
{
	if (have_delayed())
	{
		set_partner(no_partner()); // give up
		d_direction = direction_initiator;
		replay_delayed();
	}
}

void udp_stream_t::release() // destructor
{ // note, also called after only set_src_dst_from_packet is called on us
	assert(d_delayed.empty());
	doublelinked_hook_t::unlink();
	unordered_member_t::unlink();
	common_t::release();
}

/////// udp_reassembler_t //////////////////////


udp_reassembler_t::udp_reassembler_t(packet_listener_t *listener) :
	free_list_container_t<udp_stream_t>(0),
	d_listener(listener), d_stream_buckets(512), // FIXME: add some checks on the number of streams
	d_streams(stream_set_t::bucket_traits(d_stream_buckets.data(), d_stream_buckets.size()))
{
}

udp_reassembler_t::~udp_reassembler_t()
{
#if !defined(NO_REUSE) and defined(DEBUG) and defined(PRINT_STATS)
	printf("max %d udp_stream_t's in use\n", objectcount());
#endif
	flush();
}

// will check for an existing stream for the packet, or create a new one if it did not exist
// when creating a new stream, checks for existing partner stream
udp_reassembler_t::stream_set_t::iterator
udp_reassembler_t::find_or_create_stream(packet_t *packet, const layer_t *udplay)
{
	assert(udplay);

	udp_stream_t *r = claim();
	auto_release_t<udp_stream_t> releaser(r); // make sure it will be released if we don't use it

	r->set_src_dst_from_packet(packet, false);
	std::pair<stream_set_t::iterator,bool> ituple = d_streams.insert(*r);

	if (ituple.second) // new stream was inserted
	{
		r->init(d_listener);
		releaser.do_not_release();

		// find partner
		udp_stream_t *pr = claim();
		auto_release_t<udp_stream_t> releaser(pr);

		pr->set_src_dst_from_packet(packet, true);
		stream_set_t::iterator pi = d_streams.find(*pr);
		if (pi != d_streams.end() && pi != ituple.first)
			r->found_partner(&*pi);
	}
	return ituple.first;
}

void udp_reassembler_t::set_now(uint64_t now)
{
	udp_timeouts_t::streamlist_t timeouts;
	d_timeouts.set_time(now, timeouts); // remove all streams before 'now' from 'd_timeouts' and return in 'timeouts'

	// close all streams with timeouts. list should contain all initiator/responder pairs
	while (!timeouts.empty())
	{
		udp_stream_t *s = &timeouts.front();
		timeouts.pop_front();

		close_stream(s);
	}
}

void udp_reassembler_t::close_stream(udp_stream_t *stream)
{
	assert(stream);
	stream->flush();
	d_listener->accept_udp(NULL, stream); // stream closed
	stream->release();
}

void udp_reassembler_t::process(packet_t *packet)
{
	assert(packet->is_initialised());

	const layer_t *udplay = find_top_nondata_layer(packet);
	assert(udplay && udplay->type() == layer_udp);

	stream_set_t::iterator it = find_or_create_stream(packet, udplay);
	udp_stream_t *partner = (it->have_partner() ? it->partner() : nullptr);

	it->add(packet, udplay);

	// timeouts
	uint64_t to = it->timeout();
	d_timeouts.set_timeout(to, &*it, partner);
}

void udp_reassembler_t::flush()
{
	// note: this is not a O(n), d_streams begin function is not O(1)
	while (true)
	{
		stream_set_t::iterator first = d_streams.begin();
		if (first == d_streams.end())
			break;
		close_stream(&*first);
	}
}

