/*
 * Copyright 2011 Hylke Vellinga
 */


#include "reass/tcp_reassembler.h"
#include "reass/packet_listener.h"
#include "reass/helpers/misc.h"
#include "reass/config.h"
#include "reass/likely.h"
#include <boost/version.hpp>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

static_assert(BOOST_VERSION != 104800, "bug 6153 in boost::intrusive in boost 1.48 prevents compilation");  // see https://svn.boost.org/trac/boost/ticket/6153
static_assert(offsetof(sockaddr_in,sin_port) == offsetof(sockaddr_in6,sin6_port), "ipv4 and ipv6 port number alignment broken");
static_assert(sizeof(ip_address_t) == sizeof(sockaddr_in6), "structure size broken");

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

#if 0
static bool operator <(const timeval &l, const timeval &r)
{
	if (l.tv_sec != r.tv_sec)
		return l.tv_sec < r.tv_sec;
	return l.tv_usec < r.tv_usec;
}

static bool operator >=(const timeval &l, const timeval &r)
{
	return r < l;
}

static timeval operator -(const timeval &l, const timeval &r)
{
	timeval o;
	o.tv_sec = l.tv_sec - r.tv_sec;
	o.tv_usec = l.tv_usec - r.tv_usec;
	if (r.tv_usec > l.tv_usec)
	{
		o.tv_usec += + 1000000;
		o.tv_sec -= 1;
	}

	return o;
}
#endif

std::ostream &operator <<(std::ostream &os, const timeval &tv)
{
	char buf[128];
	sprintf(buf, "%ld.%06ld", tv.tv_sec, tv.tv_usec);
	os << buf;
	return os;
}

uint64_t tcp_stream_t::timeout() const
{
	bool use_short = d_have_accepted_end;
	uint64_t r = d_highest_ts.tv_sec;
	tcp_stream_t *our_partner = nullptr;
	if (have_partner())
	{
		our_partner = partner();
		use_short = use_short || our_partner->d_have_accepted_end;
		uint64_t o = our_partner->d_highest_ts.tv_sec;
		if (o > r)
			r = o;
	}

	r += (use_short ? 60 : 600);
	return r;
}


tcp_stream_t::tcp_stream_t(tcp_stream_t *&free_head) :
	common_t(free_head)
{
}

tcp_stream_t::~tcp_stream_t()
{
}

void tcp_stream_t::init(packet_listener_t *listener)
{
	common_t::init(listener);
	d_trust_seq = false;
	d_next_seq = 0;
	d_smallest_ack = 0;
	d_highest_ts.tv_sec = 0; d_highest_ts.tv_usec = 0;
	d_have_accepted_end = false;
	d_direction = direction_unknown;
	assert(d_delayed.empty()); // leftover packets would give funny results :)
}

void tcp_stream_t::set_src_dst_from_packet(const packet_t *packet, bool swap /* construct src/dst inverted stream */)
{
	const layer_t *tcplay = find_top_nondata_layer(packet);
	if (!tcplay || tcplay->type() != layer_tcp)
		throw format_exception("expected tcp layer");

	const layer_t *iplay = packet->prev(tcplay);
	while (iplay && iplay->type() != layer_ipv4 && iplay->type() != layer_ipv6)
		iplay = packet->prev(iplay);
	if (!iplay)
		throw format_exception("expected ip layer before tcp layer");

	const tcphdr &hdr1 = reinterpret_cast<const tcphdr &>(*tcplay->data());
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

void tcp_stream_t::found_partner(tcp_stream_t *other)
{
	assert(other != this);
	if (other->is_partner_set())
		return; // too late. our partner gave up on us

	assert(!is_partner_set() && !other->is_partner_set());
	set_partner(other);
	other->set_partner(this);
	other->check_delayed();

	// if the other side has a reasonable guess at our sequence numbers, use it
	if (!d_trust_seq && other->d_smallest_ack != 0 &&
			(d_next_seq == 0 || d_next_seq < other->d_smallest_ack))
		d_next_seq = other->d_smallest_ack;
}


void tcp_stream_t::find_relyable_startseq(const tcphdr &hdr)
{
	seq_nr_t seq(htonl(hdr.seq));
	if (hdr.syn) // syn-packets signify a first packet
	{
		d_trust_seq = true;
		d_next_seq = seq;
	}
	else
	{
		if (d_next_seq == 0 || seq <= d_next_seq) // wait until sequence numbers are increasing
			d_next_seq = seq;
		else
		{
			d_trust_seq = true;
			check_delayed();
		}
	}
}

// add a packet, will either queue it in d_delayed, or accept it
bool tcp_stream_t::add(packet_t *packet, const layer_t *tcplay)
{
	//printf("adding packet. next_seq = %08x\n", d_next_seq.d_val);
	assert(tcplay);

	if (packet->ts() > d_highest_ts)
		d_highest_ts = packet->ts();

	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->data());

	if (unlikely(!is_reasonable_seq(htonl(hdr.seq))))
		return false; // quick port re-use, packet not part of this stream

	if (!d_trust_seq) // check if we already have a starting packet
		find_relyable_startseq(hdr);

	if (!is_partner_set())
	{
		seq_nr_t ack(htonl(hdr.ack_seq));
		if (d_smallest_ack == 0 || ack < d_smallest_ack)
			d_smallest_ack = ack;
	}

	seq_nr_t seq(htonl(hdr.seq));
	// if we know where the packet should go -> do it
	if (d_trust_seq && is_partner_set()) // partner is also set if we gave up looking
	{
		if (seq <= d_next_seq)
			accept_packet(packet, tcplay);
		else
			d_delayed.insert(delayed_t::value_type(seq, packet));
	}
	else
		d_delayed.insert(delayed_t::value_type(seq, packet));

	// fallback, don't queue too much
	if (d_delayed.size() > MAX_DELAYED_PACKETS)
	{
		d_trust_seq = true; // if this wasn't set yet, it was seriously screwed up
		check_delayed(true);
	}

	return true; // packet belonged to this stream
}

bool tcp_stream_t::is_reasonable_seq(seq_nr_t seq)
{
	if (!d_trust_seq) return true; // could be

	const uint32_t cutoff = 4*1024*1024; // 4MB

	return
		seq_nr_t(d_next_seq.d_val - cutoff) < seq &&
		seq < seq_nr_t(d_next_seq.d_val + cutoff);
}

// find out if this packet is initiator or responder. called from accept_packet, so partner should be set
void tcp_stream_t::find_direction(packet_t *packet, const layer_t *tcplay)
{
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->data());
	if (have_partner() && partner()->d_direction != direction_unknown)
		d_direction = (partner()->d_direction == direction_initiator ? direction_responder : direction_initiator);
	else
	{
		if (hdr.syn)
			d_direction = (hdr.ack ? direction_responder : direction_initiator);
		else
			d_direction = (htons(hdr.source) > htons(hdr.dest) ? direction_initiator : direction_responder);

		if (have_partner())
			partner()->d_direction = (d_direction == direction_initiator ? direction_responder : direction_initiator);
	}
	assert(d_direction == direction_initiator || d_direction == direction_responder);
}

// called when we decided this is the packet that should be sent out
void tcp_stream_t::accept_packet(packet_t *packet, const layer_t *tcplay)
{
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->data());
	const layer_t *next = packet->next(tcplay);

	if (d_direction == direction_unknown)
		find_direction(packet, tcplay);

	if (hdr.fin || hdr.rst)
		d_have_accepted_end = true;

	size_t psize = 0;
	if (next) psize = next->size();
	assert(!next || (packet->next(next) == NULL && next->type() == layer_data)); // assume we are the last
	if (psize && hdr.syn)
	{
		// if this ever happens in a legal case, please send me the pcap
		listener()->accept_error(packet, "tcp-payload in syn-packet");
		return;
	}
	assert(!psize || !hdr.syn); // assume syn-packets will not have content. will break some day
	seq_nr_t seq = htonl(hdr.seq);
	int32_t packetloss = seq.d_val - d_next_seq.d_val;
	int32_t overlap = -packetloss;
	if (psize)
	{ // we have content
		if (overlap > 0)
		{
			//printf("overlap = %d, psize = %ld\n", overlap, psize);
			if ((uint32_t)overlap > psize)
				packet->add_layer(layer_data, next->end(), next->end());
			else
				packet->add_layer(layer_data, next->begin() + overlap, next->end());
		}
		seq.d_val += psize;
	}

	if (hdr.syn) ++seq.d_val;
	if (hdr.fin) ++seq.d_val; // this is undocumented, but needed??

	// we don't have packetloss if we have a reset-packet, or with packet-overlap
	if (packetloss < 0 || hdr.rst) packetloss = 0;

	if (seq > d_next_seq)
		d_next_seq = seq;

	listener()->accept_tcp(packet, packetloss, this);

	check_delayed();
}

// check if we can accept some packets given current sequencenumbers
void tcp_stream_t::check_delayed(bool force /* force at least one packet out */)
{
	if (!is_partner_set())
	{
		if (force)
			set_partner(no_partner()); // give up
		else
			return; // not forced, and still looking for a partner -> do nothing
	}

	if(d_delayed.empty())
		return;

	delayed_t::iterator i = d_delayed.begin();
	seq_nr_t seq = i->first;
	if (force || seq <= d_next_seq)
	{
		packet_t *packet = i->second;
		d_delayed.erase(i);
		const layer_t *tcplay = find_top_nondata_layer(packet);
		assert(tcplay && tcplay->type() == layer_tcp);
		accept_packet(packet, tcplay);
	}
}

// we gave up on stream. emit everything we have
void tcp_stream_t::flush()
{
	while (!d_delayed.empty())
		check_delayed(true);
}

void tcp_stream_t::release() // destructor
{ // note, also called after only set_src_dst_from_packet is called on us
	assert(d_delayed.empty());
	doublelinked_hook_t::unlink();
	unordered_member_t::unlink();
	common_t::release();
}


/////// tcp_reassembler_t //////////////////////


tcp_reassembler_t::tcp_reassembler_t(packet_listener_t *listener) :
	free_list_container_t<tcp_stream_t>(0),
	d_listener(listener), d_stream_buckets(512), // FIXME: add some checks on the number of streams
	d_streams(stream_set_t::bucket_traits(d_stream_buckets.data(), d_stream_buckets.size()))
{
}

tcp_reassembler_t::~tcp_reassembler_t()
{
#if !defined(NO_REUSE) and defined(DEBUG) and defined(PRINT_STATS)
	printf("max %d tcp_stream_t's in use\n", objectcount());
#endif
	flush();
}

// will check for an existing stream for the packet, or create a new one if it did not exist
// when creating a new stream, checks for existing partner stream
tcp_reassembler_t::stream_set_t::iterator
tcp_reassembler_t::find_or_create_stream(packet_t *packet, const layer_t *tcplay)
{
	assert(tcplay);

	tcp_stream_t *r = claim();
	auto_release_t<tcp_stream_t> releaser(r); // make sure it will be released if we don't use it

	r->set_src_dst_from_packet(packet, false);
	std::pair<stream_set_t::iterator,bool> ituple = d_streams.insert(*r);

	if (ituple.second) // new stream was inserted
	{
		r->init(d_listener);
		releaser.do_not_release();

		// find partner
		tcp_stream_t *pr = claim();
		auto_release_t<tcp_stream_t> releaser(pr);

		pr->set_src_dst_from_packet(packet, true);
		stream_set_t::iterator pi = d_streams.find(*pr);
		if (pi != d_streams.end() && pi != ituple.first)
			r->found_partner(&*pi);
	}
	return ituple.first;
}

void tcp_reassembler_t::set_now(uint64_t now)
{
	tcp_timeouts_t::streamlist_t timeouts;
	d_timeouts.set_time(now, timeouts); // remove all streams before 'now' from 'd_timeouts' and return in 'timeouts'

	// close all streams with timeouts. list should contain all initiator/responder pairs
	while (!timeouts.empty())
	{
		tcp_stream_t *s = &timeouts.front();
		timeouts.pop_front();

		close_stream(s);
	}
}

void tcp_reassembler_t::close_stream(tcp_stream_t *stream)
{
	assert(stream);
	stream->flush();
	d_listener->accept_tcp(NULL, 0, stream); // stream closed
	stream->release();
}

void tcp_reassembler_t::process(packet_t *packet)
{
	assert(packet->is_initialised());

	const layer_t *tcplay = find_top_nondata_layer(packet);
	assert(tcplay && tcplay->type() == layer_tcp);

	stream_set_t::iterator it = find_or_create_stream(packet, tcplay);
	tcp_stream_t *partner = (it->have_partner() ? it->partner() : nullptr);

	// returns false if packet probably does not belong to stream (quick port reuse)
	bool accepted_packet = it->add(packet, tcplay);

	if (unlikely(!accepted_packet))
	{
		if (partner)
			close_stream(partner);
		close_stream(&*it);
		process(packet);
		return;
	}

	// timeouts
	uint64_t to = it->timeout();
	d_timeouts.set_timeout(to, &*it, partner);
}

void tcp_reassembler_t::flush()
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

