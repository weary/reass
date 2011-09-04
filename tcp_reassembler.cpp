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

static bool operator <(const timeval &l, const timeval &r)
{
	if (l.tv_sec != r.tv_sec)
		return l.tv_sec < r.tv_sec;
	return l.tv_usec < r.tv_usec;
}

static timeval operator -(const timeval &l, const timeval &r)
{
	//BORKAGE
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

std::ostream &operator <<(std::ostream &os, const timeval &tv)
{
	char buf[128];
	sprintf(buf, "%ld.%06ld", tv.tv_sec, tv.tv_usec);
	os << buf;
	return os;
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
	d_highest_ts = {0,0};
	d_have_accepted_end = false;
	d_userdata = NULL;
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

void tcp_stream_t::set_src_dst_from_packet(const packet_t *packet)
{
	int n = -1;
	const layer_t *tcplay = packet->layer(n);
	while (tcplay && tcplay->type() != layer_tcp)
		tcplay = packet->layer(--n);
	if (!tcplay)
		throw format_exception("expected tcp layer");

	const layer_t *iplay = packet->layer(n);
	while (iplay && iplay->type() != layer_ipv4 && iplay->type() != layer_ipv6)
		iplay = packet->layer(--n);
	if (!iplay)
		throw format_exception("expected ip layer before tcp layer");

#ifdef DEBUG
	::memset(&d_src, 'X', sizeof(d_src));
	::memset(&d_dst, 'X', sizeof(d_dst));
#endif
	const tcphdr &hdr1 = reinterpret_cast<const tcphdr &>(*tcplay->data());
	if (iplay->type() == layer_ipv4)
	{
		const iphdr &hdr2 = reinterpret_cast<const iphdr &>(*iplay->data());
		d_src.v4.sin_family = AF_INET;
		d_src.v4.sin_port = hdr1.source;
		d_src.v4.sin_addr.s_addr = hdr2.saddr;

		d_dst.v4.sin_family = AF_INET;
		d_dst.v4.sin_port = hdr1.dest;
		d_dst.v4.sin_addr.s_addr = hdr2.daddr;
	}
	else
	{
		const ip6_hdr &hdr2 = reinterpret_cast<const ip6_hdr &>(*iplay->data());
		assert(iplay->type() == layer_ipv6);
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

void tcp_stream_t::find_relyable_startseq(const tcphdr &hdr)
{
	seq_nr_t seq(htonl(hdr.seq));
	if (hdr.syn) // syn-packets signify a first packet
	{
		d_trust_seq = true;
		d_next_seq = seq;
		//printf("next_seq set to %08x due to syn flag\n", d_next_seq.d_val);
	}
	else
	{
		seq_nr_t seq = htonl(hdr.seq);
		if (d_delayed.empty())
		{
			d_next_seq = seq; // first guess at correct seq
			//printf("next_seq set to %08x (first guess)\n", d_next_seq.d_val);
		}
		else
		{
			if (seq <= d_next_seq) // wait until sequence numbers are increasing
			{
				d_next_seq = seq;
				//printf("next_seq set to %08x (improved guess)\n", d_next_seq.d_val);
			}
			else
			{
				d_trust_seq = true;
				check_delayed();
			}
		}
	}
}

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
	if (d_trust_seq)
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

// called when we decided this is the packet that should be sent out
void tcp_stream_t::accept_packet(packet_t *packet, const layer_t *tcplay)
{
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*tcplay->data());
	layer_t *next = tcplay->next();

	printf("fin = %d, rst = %d, %s\n",
			hdr.fin, hdr.rst, to_str(*packet).c_str());
	if (hdr.fin || hdr.rst)
	{
		printf("accepting end\n");
		d_have_accepted_end = true;
	}

	size_t psize = 0;
	if (next) psize = next->size();
	assert(!next || (next->last_layer() && next->type() == layer_data)); // assume we are the last
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

#if 1
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
{
	assert(d_delayed.empty());
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
	d_listener(listener), d_now({0,0})
{
}

tcp_reassembler_t::~tcp_reassembler_t()
{
	for(stream_set_t::iterator i = d_streams.begin(); i!= d_streams.end(); ++i)
	{
		tcp_stream_t *stream = const_cast<tcp_stream_t *>(*i);
		close_stream(stream);
	}
}

tcp_reassembler_t::stream_set_t::iterator
tcp_reassembler_t::find_stream(packet_t *packet, const layer_t *tcplay)
{
	assert(tcplay);

	tcp_stream_t *r = claim();
	auto_release_t<tcp_stream_t> releaser(r);

	r->set_src_dst_from_packet(packet);
	stream_set_t::iterator i = d_streams.find(r);

	// FIXME: check for port-reuse here

	if (i == d_streams.end())
	{
		// FIXME: check for partner here

		r->init(d_listener);
		i = d_streams.insert(r).first;
		releaser.do_not_release();
	}
	return i;
}

void tcp_reassembler_t::check_timeouts()
{
	typedef stream_set_t::nth_index<1>::type idx_t;
	idx_t &tsidx = d_streams.get<1>();

	while (!tsidx.empty() && (*tsidx.begin())->timeout() < d_now)
	{
		tcp_stream_t *stream = *tsidx.begin();
		tsidx.erase(tsidx.begin());

		printf("%s: timeout\n", to_str(*stream).c_str());
		close_stream(stream);
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

	bool now_changed = false;
	if (packet->ts() > d_now) // time elapsed!
	{
		d_now = packet->ts();
		now_changed = true;
	}

	stream_set_t::iterator it = find_stream(packet, tcplay);
	(*it)->add(packet, tcplay);

	// timeout changed (possibly). need to move r
	typedef stream_set_t::nth_index<1>::type idx_t;
	idx_t &tsidx = d_streams.get<1>();
	idx_t::iterator it2 = d_streams.project<1>(it);
	tsidx.modify(it2, no_op());

	if (now_changed)
		check_timeouts();
}

