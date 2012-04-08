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

#include "common_reassembler.hpp"

#endif // __REASS_COMMON_REASSEMBLER_H__

