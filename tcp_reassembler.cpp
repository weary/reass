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

static bool operator >(const timeval &l, const timeval &r)
{
	if (l.tv_sec != r.tv_sec)
		return l.tv_sec > r.tv_sec;
	return l.tv_usec > r.tv_usec;
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

template<typename TO>
void tcp_stream_t::set_timeout(TO &to)
{
	bool use_short = d_have_accepted_end;
	uint64_t r = d_highest_ts.tv_sec;
	tcp_stream_t *partner = NULL;
	if (have_partner())
	{
		partner = d_partner;
		use_short = use_short || d_partner->d_have_accepted_end;
		uint64_t o = d_partner->d_highest_ts.tv_sec;
		if (o > r)
			r = o;
	}

	r += (use_short ? 60 : 600);
	to.set_timeout(r, this, partner);
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
	d_highest_ts.tv_sec = 0; d_highest_ts.tv_usec = 0;
	d_have_accepted_end = false;
	d_userdata = NULL;
	d_partner = NULL;
	d_direction = direction_unknown;
	assert(d_delayed.empty()); // leftover packets would give funny results :)
}

static const layer_t *find_tcp_layer(const packet_t *packet)
{
	int n = -1;
	const layer_t *tcplay = packet->layer(n);
	while (tcplay && tcplay->type() != layer_tcp)
		tcplay = packet->layer(--n);
	return tcplay;
}

void tcp_stream_t::set_src_dst_from_packet(const packet_t *packet, bool swap /* construct src/dst inverted stream */)
{
	const layer_t *tcplay = find_tcp_layer(packet);
	if (!tcplay)
		throw format_exception("expected tcp layer");

	const layer_t *iplay = packet->prev(tcplay);
	while (iplay && iplay->type() != layer_ipv4 && iplay->type() != layer_ipv6)
		iplay = packet->prev(iplay);
	if (!iplay)
		throw format_exception("expected ip layer before tcp layer");

	ip_address_t &src = (swap ? d_dst : d_src);
	ip_address_t &dst = (swap ? d_src : d_dst);
#ifdef DEBUG
	::memset(&src, 'Z', sizeof(src));
	::memset(&dst, 'Z', sizeof(dst));
#endif
	const tcphdr &hdr1 = reinterpret_cast<const tcphdr &>(*tcplay->data());
	if (iplay->type() == layer_ipv4)
	{
		const iphdr &hdr2 = reinterpret_cast<const iphdr &>(*iplay->data());
		src.v4.sin_family = AF_INET;
		src.v4.sin_port = hdr1.source;
		src.v4.sin_addr.s_addr = hdr2.saddr;

		dst.v4.sin_family = AF_INET;
		dst.v4.sin_port = hdr1.dest;
		dst.v4.sin_addr.s_addr = hdr2.daddr;
	}
	else
	{
		const ip6_hdr &hdr2 = reinterpret_cast<const ip6_hdr &>(*iplay->data());
		assert(iplay->type() == layer_ipv6);
		src.v6.sin6_family = AF_INET6;
		src.v6.sin6_port = hdr1.source;
		src.v6.sin6_addr = hdr2.ip6_src;
		src.v6.sin6_flowinfo = 0;
		src.v6.sin6_scope_id = 0;

		dst.v6.sin6_family = AF_INET6;
		dst.v6.sin6_port = hdr1.dest;
		dst.v6.sin6_addr = hdr2.ip6_dst;
		dst.v6.sin6_flowinfo = 0;
		dst.v6.sin6_scope_id = 0;
	}
	d_partner = NULL; // so ->release can check the partner
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

// add a packet, will either queue it in d_delayed, or accept it
void tcp_stream_t::add(packet_t *packet, const layer_t *tcplay)
{
	//printf("adding packet. next_seq = %08x\n", d_next_seq.d_val);
	assert(tcplay);

	if (packet->ts() > d_highest_ts)
		d_highest_ts = packet->ts();

	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->data());

	if (!d_trust_seq) // check if we already have a starting packet
		find_relyable_startseq(hdr);

	seq_nr_t seq(htonl(hdr.seq));
	// if we know where the packet should go -> do it
	if (d_trust_seq && d_partner) // d_partner is also true if we gave up looking
	{
		if (seq <= d_next_seq)
			accept_packet(packet, tcplay);
		else
			d_delayed.insert(delayed_t::value_type(seq, packet));
	}
	else
		d_delayed.insert(delayed_t::value_type(seq, packet));

	// fallback, don't queue too much
	if (d_delayed.size() > 16)
	{
		d_trust_seq = true; // if this wasn't set yet, it was seriously screwed up
		check_delayed(true);
	}
}

// find out if this packet is initiator or responder. called from accept_packet, so partner should be set
void tcp_stream_t::find_direction(packet_t *packet, const layer_t *tcplay)
{
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->data());
	if (have_partner() && d_partner->d_direction != direction_unknown)
		d_direction = (d_partner->d_direction == direction_initiator ? direction_responder : direction_initiator);
	else
	{
		if (hdr.syn)
			d_direction = (hdr.ack ? direction_responder : direction_initiator);
		else
			d_direction = (htons(hdr.source) < htons(hdr.dest) ? direction_initiator : direction_responder);

		if (have_partner())
			d_partner->d_direction = (d_direction == direction_initiator ? direction_responder : direction_initiator);
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

	if (packetloss < 0) packetloss = 0;

	if (seq > d_next_seq)
		d_next_seq = seq;

#if 0
	if (overlap > 0)
		printf("packet %08ld: accepted packet %08x (%d data including %d overlap), next will be %08x\n",
				packet->packetnr(), htonl(hdr.seq), (int)psize, overlap, d_next_seq.d_val);
	else
		printf("packet %08ld: accepted packet %08x (%d data, %d packetloss), next will be %08x\n",
				packet->packetnr(), htonl(hdr.seq), (int)psize, packetloss, d_next_seq.d_val);
#endif

	d_listener->accept_tcp(packet, packetloss, this);

	check_delayed();
}

// check if we can accept some packets given current sequencenumbers
void tcp_stream_t::check_delayed(bool force /* force at least one packet out */)
{
	//printf("checking delayed, contains %d entries\n", (int)d_delayed.size());

	if (!d_partner)
	{
		if (force)
			d_partner = no_partner(); // give up
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
		const layer_t *tcplay = find_tcp_layer(packet);
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
	if (d_partner &&
			d_partner != no_partner() &&
			d_partner != partner_destroyed())
		d_partner->d_partner = partner_destroyed();
#ifdef DEBUG
	d_partner = partner_destroyed();
	::memset(&d_src, 'X', sizeof(d_src));
	::memset(&d_dst, 'X', sizeof(d_dst));
#endif
	doublelinked_hook_t::unlink();
	unordered_member_t::unlink();

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
	free_list_container_t<tcp_stream_t>(0),
	d_listener(listener), d_stream_buckets(512), // FIXME: add some checks on the number of streams
	d_streams(stream_set_t::bucket_traits(d_stream_buckets.data(), d_stream_buckets.size()))
{
}

tcp_reassembler_t::~tcp_reassembler_t()
{
#if !defined(NO_REUSE) and defined(DEBUG)
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
	auto_release_t<tcp_stream_t> releaser(r);

	r->set_src_dst_from_packet(packet, false);
	std::pair<stream_set_t::iterator,bool> ituple = d_streams.insert(*r);

	// check for port-reuse
// FIXME: alleen port-reuse bij sterk afwijkende sequence nummers
#if 0
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->data());
	if (i != d_streams.end() && hdr.syn) // FIXME: add check on large difference in sequence numbers
	{ // port re-used
		printf("port reuse on %s (=%s)!\n", to_str(*r).c_str(), to_str(**i).c_str());
		tcp_stream_t *old = *i;
		if ((*i)->have_partner())
		{ // close partner
			tcp_stream_t *partner = old->partner();
			assert(partner != old);
			stream_set_t::iterator pi = d_streams.find(partner); // iterator_to somehow does not yield a valid iterator
			assert(*pi != *i && pi != i);
			d_streams.erase(pi);
			close_stream(partner);
		}
		d_streams.erase(i);
		close_stream(old);
		i = d_streams.end();
	}
#endif

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
			r->set_partner(&*pi);
	}
	return ituple.first;
}

void tcp_stream_t::set_partner(tcp_stream_t *other)
{
	assert(other != this);
	if (other->d_partner == no_partner())
		return; // too late. our partner gave up on us

	assert(d_partner == NULL && other->d_partner == NULL);
	d_partner = other;
	other->d_partner = this;
	other->check_delayed();
}

// global timeouts, no newer packets have been seen (not even delayed)
void tcp_reassembler_t::check_timeouts(uint64_t now)
{
	tcp_timeouts_t::streamlist_t timeouts;
	d_timeouts.set_time(now, timeouts);

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

struct no_op
{
  void operator()(tcp_stream_t *) {}
};

void tcp_reassembler_t::process(packet_t *packet)
{
	assert(packet->is_initialised());
	const layer_t *tcplay = find_tcp_layer(packet);
	assert(tcplay);

	check_timeouts(packet->ts().tv_sec);

	stream_set_t::iterator it = find_or_create_stream(packet, tcplay);
	it->add(packet, tcplay);

	it->set_timeout(d_timeouts);
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

