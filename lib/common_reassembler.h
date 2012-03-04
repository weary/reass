/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_COMMON_REASSEMBLER_H__
#define __REASS_COMMON_REASSEMBLER_H__

#include <boost/intrusive/unordered_set.hpp>
#include "free_list.h"
#include "ip_address.h"
#include "timeout.h"
#include "force_inline.h"
#include "packet_listener.h"


// shared functionality between udp_stream_t and tcp_stream_t
// both have partners, from/to ip's and userdata
template<typename CRTP>
struct common_stream_t :
	public free_list_member_t<CRTP> // needed for memory-management
{
	common_stream_t(CRTP *&free_head);
	~common_stream_t() {}

	void release(); // destructor
protected: // called from {tcp,udp}_reassembler_t
	void set_src_dst4(u_int32_t from, u_int16_t fromport, u_int32_t to, u_int16_t toport, bool swap);
	void set_src_dst6(const in6_addr &from, u_int16_t fromport, const in6_addr &to, u_int16_t toport, bool swap);
	void init(packet_listener_t *listener);

	void set_partner(CRTP *partner) { assert(partner); d_partner = partner; }
	bool is_partner_set() const { return !!d_partner; }

	static CRTP *no_partner() { return (CRTP*)-1; }
	static CRTP *partner_destroyed() { return (CRTP*)-2; }

public:
	void set_userdata(void *userdata) { d_userdata = userdata; }
	void *userdata() const { return d_userdata; }

	CRTP *partner() const { assert(have_partner()); return d_partner; }
	bool have_partner() const { return d_partner && d_partner != no_partner() && d_partner != partner_destroyed(); }

	void print(std::ostream &os) const;

	const ip_address_t &from() const { return d_src; }
	const ip_address_t &to() const { return d_dst; }

	packet_listener_t *listener() const { return d_listener; }

private: // internal
	packet_listener_t *d_listener;

	ip_address_t d_src;
	ip_address_t d_dst;

	CRTP *d_partner;

	void *d_userdata;
};

#if 0
struct tcp_stream_equal_addresses
{
	bool operator()(const tcp_stream_t &l, const tcp_stream_t &r) const
	{
		return l.d_src == r.d_src && l.d_dst == r.d_dst;
	}
};

struct tcp_stream_hash_addresses
{
	std::size_t operator()(const tcp_stream_t &s) const
	{
		std::size_t r = hash_value(s.d_src);
		boost::hash_combine(r, s.d_dst);
		return r;
	}
};

struct tcp_reassembler_t : private free_list_container_t<tcp_stream_t>
{
	tcp_reassembler_t(packet_listener_t *listener);
	~tcp_reassembler_t();

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
		tcp_stream_t,
		boost::intrusive::constant_time_size<false>,
		boost::intrusive::power_2_buckets<true>,
		boost::intrusive::equal<tcp_stream_equal_addresses>,
		boost::intrusive::hash<tcp_stream_hash_addresses>
	> stream_set_t;

	std::vector<stream_set_t::bucket_type> d_stream_buckets;
	stream_set_t d_streams;
	typedef timeouts_t<616, 8, tcp_stream_t> tcp_timeouts_t; // 10 mins + 10 secs rounded up to multiple of 8
	tcp_timeouts_t d_timeouts;

	stream_set_t::iterator find_or_create_stream(packet_t *packet, const layer_t *tcplay);
	void close_stream(tcp_stream_t *stream);
};

#endif

#include "common_reassembler.hpp"

#endif // __REASS_COMMON_REASSEMBLER_H__

