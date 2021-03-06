/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_COMMON_REASSEMBLER_H__
#define __REASS_COMMON_REASSEMBLER_H__

#include <boost/intrusive/unordered_set.hpp>
#include "reass/free_list.h"
#include "reass/ip_address.h"
#include "reass/timeout.h"
#include "reass/force_inline.h"
#include "reass/packet_listener.h"

typedef boost::intrusive::unordered_set_base_hook<
		boost::intrusive::link_mode<
			boost::intrusive::auto_unlink>,
		boost::intrusive::store_hash<false>
	> unordered_member_t;

inline
const layer_t *find_top_nondata_layer(const packet_t *packet)
{
	const layer_t *lay = packet->layer(-1);
	while (lay && lay->type() == layer_data)
		lay = packet->prev(lay);
	return lay;
}


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

struct stream_equal_addresses
{
	template<typename CRTP>
	bool operator()(
			const common_stream_t<CRTP> &l,
			const common_stream_t<CRTP> &r) const
	{
		return l.from() == r.from() && l.to() == r.to();
	}
};

struct stream_hash_addresses
{
	template<typename CRTP>
	std::size_t operator()(const common_stream_t<CRTP> &s) const
	{
		std::size_t r = hash_value(s.from());
		boost::hash_combine(r, s.to());
		return r;
	}
};

inline bool operator >(const timeval &l, const timeval &r)
{
	if (l.tv_sec != r.tv_sec)
		return l.tv_sec > r.tv_sec;
	return l.tv_usec > r.tv_usec;
}


#include "common_reassembler.hpp"

#endif // __REASS_COMMON_REASSEMBLER_H__

