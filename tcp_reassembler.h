/*
 * Copyright 2011 Hylke Vellinga
 */


#include "uint128.h"
#include "ip_address.h"
#include "free_list.h"
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/functional/hash/hash.hpp>

class packet_t;
class packet_listener_t;

struct tcp_stream_t : public free_list_member_t<tcp_stream_t>
{
	tcp_stream_t(tcp_stream_t *&free_head);
	~tcp_stream_t();

	// packet only used to initialise src/dst, packet not added
	void init(packet_listener_t *listener, const packet_t *packet);

	void add(packet_t *packet);

	void print(std::ostream &os) const;
protected:
	packet_listener_t *d_listener;

	ip_address_t d_src;
	ip_address_t d_dst;

	uint32_t d_next_seq;

	friend struct tcp_stream_equal_addresses;
	friend struct tcp_stream_hash_addresses;
};

std::ostream &operator <<(std::ostream &, const tcp_stream_t &);

struct tcp_stream_equal_addresses
{
	bool operator()(const tcp_stream_t*l, const tcp_stream_t*r) const
	{
		return l->d_src == r->d_src && l->d_dst == r->d_dst;
	}
};

struct tcp_stream_hash_addresses
{
	std::size_t operator()(const tcp_stream_t*s) const
	{
		std::size_t r = hash_value(s->d_src);
		boost::hash_combine(r, s->d_dst);
		return r;
	}
};

struct tcp_reassembler_t : private free_list_container_t<tcp_stream_t>
{
	tcp_reassembler_t(packet_listener_t *listener);
	~tcp_reassembler_t();

	void process(packet_t *packet);

protected:
	packet_listener_t *d_listener;

	tcp_stream_t *find_stream(packet_t *packet);

	typedef boost::multi_index_container<
		tcp_stream_t *,
		boost::multi_index::indexed_by<
			boost::multi_index::hashed_unique<
				boost::multi_index::identity<tcp_stream_t *>,
				tcp_stream_hash_addresses,
				tcp_stream_equal_addresses
			>
		>> stream_set_t;

	stream_set_t d_streams;
};
