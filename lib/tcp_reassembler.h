/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_TCP_REASSEMBLER_H__
#define __REASS_TCP_REASSEMBLER_H__

#include "reass/ip_address.h"
#include "reass/free_list.h"
#include "reass/timeout.h"
#include "reass/common_reassembler.h"
#include <boost/functional/hash/hash.hpp>
#include <boost/intrusive/unordered_set.hpp>
#include <vector>
#include <map>

struct packet_t;
class packet_listener_t;
struct layer_t;
class tcphdr;

struct seq_nr_t
{
	seq_nr_t() : d_val(0) {}
	seq_nr_t(uint32_t val) : d_val(val) {}

	uint32_t d_val;
};

inline bool operator <(const seq_nr_t l, const seq_nr_t r)
{
	int32_t diff = l.d_val - r.d_val;
	return diff < 0;
}

inline uint32_t distance(const seq_nr_t l, const seq_nr_t r)
{
	uint32_t max1 = l.d_val - r.d_val;
	uint32_t max2 = r.d_val - l.d_val;
	return std::min<uint32_t>(max1, max2);
}

inline bool operator ==(const seq_nr_t l, uint32_t r) { return l.d_val == r; }
inline bool operator !=(const seq_nr_t l, uint32_t r) { return l.d_val != r; }
inline bool operator ==(const seq_nr_t l, seq_nr_t r) { return l.d_val == r.d_val; }

std::ostream &operator <<(std::ostream &os, const seq_nr_t &s);

struct tcp_stream_t :
	public common_stream_t<tcp_stream_t>,
	public doublelinked_hook_t, // for timeouts
	public unordered_member_t // for stream-lookup
{
	tcp_stream_t(tcp_stream_t *&free_head);
	~tcp_stream_t();

	void release(); // destructor
protected: // called from tcp_reassembler_t
	friend struct tcp_reassembler_t;
	typedef common_stream_t<tcp_stream_t> common_t;

	void set_src_dst_from_packet(const packet_t *packet, bool swap); // constructor(1/2)
	void init(packet_listener_t *listener); // constructor(2/2), will not touch src/dst

	void found_partner(packet_t *packet, tcp_stream_t *partner);

	// return false if !is_reasonable_seq or we don't trust sequence numbers yet
	bool add(packet_t *packet, const layer_t *tcplay);

	// returns timestamp when this stream(+partner) is timed-out
	uint64_t timeout() const;

	static tcp_stream_t *no_partner() { return (tcp_stream_t*)-1; }
	static tcp_stream_t *partner_destroyed() { return (tcp_stream_t*)-2; }

public:
	bool closed() const { return d_have_accepted_end; }

	bool initiator() const { assert(d_direction == direction_initiator || d_direction == direction_responder); return d_direction == direction_initiator; }
	bool responder() const { return !initiator(); }

protected: // internal
	void accept_packet(packet_t *p, const layer_t *tcplay);
	void find_relyable_startseq(const tcphdr &hdr);
	bool find_seq_from_ack(seq_nr_t ack);
	void check_delayed(bool force = false);
	bool have_delayed() const { return !d_delayed.empty(); }
	void find_direction(packet_t *packet, const layer_t *tcplay);
	void flush();

	bool d_trust_seq;
	seq_nr_t d_next_seq;
	seq_nr_t d_smallest_ack; // used to detect packet loss in first packets
	bool d_have_accepted_end;
	bool d_have_sent_end;

	enum direction_t { direction_unknown, direction_initiator, direction_responder };
	direction_t d_direction;

	timeval d_highest_ts;

	// FIXME: this is a really small multimap,
	// a sorted list probably has the same performance
	typedef std::multimap<seq_nr_t, packet_t *> delayed_t; // FIXME: intrusive?
	delayed_t d_delayed;

	friend struct stream_equal_addresses;
	friend struct stream_hash_addresses;
};

inline std::ostream &operator <<(std::ostream &os, const tcp_stream_t &t)
{
	t.print(os);
	return os;
}


struct tcp_reassembler_t :
	private free_list_container_t<tcp_stream_t>
{
	tcp_reassembler_t(packet_listener_t *listener);
	~tcp_reassembler_t();

	void process(packet_t *packet);

	void set_listener(packet_listener_t *listener) { d_listener = listener; }

	// advance current time to specified nr-of-seconds since epoch (1970)
	// will not move time backwards, checks timeouts.
	// in debug returns number of streams closed due to timeout
#ifdef DEBUG
	uint64_t set_now(uint64_t now);
#else
	void set_now(uint64_t now);
#endif
	uint64_t now() const { return d_timeouts.now(); }

	void flush();
protected:
	packet_listener_t *d_listener;

	typedef boost::intrusive::unordered_set<
		tcp_stream_t,
		boost::intrusive::constant_time_size<false>,
		boost::intrusive::power_2_buckets<true>,
		boost::intrusive::equal<stream_equal_addresses>,
		boost::intrusive::hash<stream_hash_addresses>
	> stream_set_t;

	std::vector<stream_set_t::bucket_type> d_stream_buckets;
	stream_set_t d_streams;
	typedef timeouts_t<616, 8, tcp_stream_t> tcp_timeouts_t; // 10 mins + 10 secs rounded up to multiple of 8
	tcp_timeouts_t d_timeouts;

	stream_set_t::iterator find_or_create_stream(packet_t *packet, const layer_t *tcplay);
	void close_stream(tcp_stream_t *stream);
};

#endif // __REASS_TCP_REASSEMBLER_H__
