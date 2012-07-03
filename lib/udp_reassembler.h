/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_UDP_REASSEMBLER_H__
#define __REASS_UDP_REASSEMBLER_H__

#include <list>
#include "common_reassembler.h"

// FIXME: refactor options:
// udp_reassembler_t::stream_set_t is same as tcp (except for contained type)
// udp_reassembler_t::find_or_create_stream is same as tcp
// udp_reassembler_t::set_now is same as tcp
// udp_reassembler_t::close_stream is same as tcp, except calls different accept function on listener
// udp_reassembler_t::process is same as tcp, except for quick-port-reuse
// udp_reassembler_t::flush is same as tcp
//

struct udp_stream_t :
	public common_stream_t<udp_stream_t>,
	public doublelinked_hook_t, // for timeouts
	public unordered_member_t // for stream-lookup
{
	udp_stream_t(udp_stream_t *&free_head);
	~udp_stream_t();

	void release(); // destructor
protected: // called from udp_reassembler_t
	friend struct udp_reassembler_t;
	typedef common_stream_t<udp_stream_t> common_t;

	void set_src_dst_from_packet(const packet_t *packet, bool swap); // constructor(1/2)
	void init(packet_listener_t *listener); // constructor(2/2), will not touch src/dst

	void found_partner(udp_stream_t *partner);

	void add(packet_t *packet, const layer_t *udplay);

	// returns timestamp when this stream(+partner) is timed-out
	uint64_t timeout() const;

	static udp_stream_t *no_partner() { return (udp_stream_t*)-1; }
	static udp_stream_t *partner_destroyed() { return (udp_stream_t*)-2; }

public:
	// these are only valid if we have a partner
	bool initiator() const { assert(d_direction == direction_initiator || d_direction == direction_responder); return d_direction == direction_initiator; }
	bool responder() const { return !initiator(); }

protected: // internal
	void accept_packet(packet_t *p, const layer_t *udplay);
	bool have_delayed() const { return !d_delayed.empty(); }
	void replay_delayed();
	void flush();

	enum direction_t { direction_unknown, direction_initiator, direction_responder };
	direction_t d_direction;

	timeval d_highest_ts;

	// waiting for partner
	typedef std::list<packet_t *> delayed_t; // FIXME: intrusive?
	delayed_t d_delayed;

	friend struct stream_equal_addresses;
	friend struct stream_hash_addresses;
};

inline std::ostream &operator <<(std::ostream &os, const udp_stream_t &t)
{
	t.print(os);
	return os;
}

struct udp_reassembler_t :
	private free_list_container_t<udp_stream_t>
{
	udp_reassembler_t(packet_listener_t *listener);
	~udp_reassembler_t();

	void process(packet_t *packet);

	void set_listener(packet_listener_t *listener) { d_listener = listener; }

	// advance current time to specified nr-of-seconds since epoch (1970)
	// will not move time backwards, checks timeouts
	void set_now(uint64_t now);
	uint64_t now() const { return d_timeouts.now(); }

	void flush();
protected:
	packet_listener_t *d_listener;

	typedef boost::intrusive::unordered_set<
		udp_stream_t,
		boost::intrusive::constant_time_size<false>,
		boost::intrusive::power_2_buckets<true>,
		boost::intrusive::equal<stream_equal_addresses>,
		boost::intrusive::hash<stream_hash_addresses>
	> stream_set_t;

	std::vector<stream_set_t::bucket_type> d_stream_buckets;
	stream_set_t d_streams;
	typedef timeouts_t<616, 8, udp_stream_t> udp_timeouts_t; // 10 mins + 10 secs rounded up to multiple of 8
	udp_timeouts_t d_timeouts;

	stream_set_t::iterator find_or_create_stream(packet_t *packet, const layer_t *udplay);
	void close_stream(udp_stream_t *stream);
};

#endif // __REASS_UDP_REASSEMBLER_H__
