/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PACKET_H__
#define __REASS_PACKET_H__

#include <pcap.h>
#include <fstream>
#include <vector>
#include <string.h>
#include <stdint.h>
#include "reass/free_list.h"
#include "reass/config.h"

enum layer_type
{
	layer_ethernet, // ether_header
	layer_cooked, // sll_header
	layer_ipv4, // iphdr
	layer_ipv6, // ip6_hdr
	layer_tcp, // tcphdr
	layer_udp, // udphdr
	layer_pppoe,
	layer_data // content
};

struct layer_t
{
	const u_char *begin() const { return d_begin; }
	const u_char *end() const { return d_end; }
	const u_char *data() const { return begin(); }
	layer_type type() const { return d_type; }
	size_t size() const { return d_end-d_begin; }

	void set(const u_char *begin, const u_char *end, layer_type type)
	{
		d_begin = begin;
		d_end = end;
		d_type = type;
	}

protected:
	friend struct packet_t;

	const u_char *d_begin;
	const u_char *d_end;
	layer_type d_type;
};
std::ostream &operator <<(std::ostream &os, const layer_t &l);

// caught by pcap_parser, not seen outside reass
struct unknown_layer_t : public std::exception
{
	unknown_layer_t(uint32_t next, const char *cur) throw() : d_next(next), d_cur(cur) {}
	virtual ~unknown_layer_t() throw() {}

	virtual const char* what() const throw()
	{
		static char buf[256];
		snprintf(buf, 256, "unsupported protocol 0x%x in %s header", d_next, d_cur);
		return buf;
	}

protected:
	uint32_t d_next;
	const char *d_cur;
};

// note: packet_t memory will get reused if ->release() is called
//       call delete to remove a packet from the pool.
//       only call release from the same thread.
struct packet_t : public free_list_member_t<packet_t>
{
	packet_t(packet_t *&free_head);
	~packet_t();

	void init(int linktype,
			const struct pcap_pkthdr *hdr, const u_char *data,
			bool *have_copied_data = NULL);

	void parse_cooked(const u_char *begin, const u_char *end);
	void parse_ethernet(const u_char *begin, const u_char *end);
	void parse_vlan(const u_char *begin, const u_char *end);
	void parse_ipv4(const u_char *begin, const u_char *end);
	void parse_ipv6(const u_char *begin, const u_char *end);
	void parse_tcp(const u_char *begin, const u_char *end);
	void parse_udp(const u_char *begin, const u_char *end);
	void parse_pppoe(const u_char *begin, const u_char *end);

	void print(std::ostream &os) const;

	layer_t *layer(int n);
	const layer_t *layer(int n) const;
	const layer_t *next(const layer_t *layer) const; // move away from ethernet
	const layer_t *prev(const layer_t *layer) const; // move towards ethernet


	void release()
	{
		if (d_still_must_copy_data)
			*d_still_must_copy_data = false;
#ifdef DEBUG
		assert(is_initialised()); // only free once
		if (d_pcap_buf)
			::memset(d_pcap_buf, 'Y', d_pcap_bufsize);
		::memset(d_layers, 'Y', MAX_LAYERS*sizeof(layer_t));
		d_is_initialised = 2;
#endif //DEBUG
		free_list_member_t<packet_t>::release();
	}

#ifdef DEBUG
	bool is_initialised() const { return d_is_initialised == 1; }
#endif //DEBUG

	timeval ts() const { return d_pckthdr.ts; }

	const u_char *data() const { return d_pcap; }
	const pcap_pkthdr &pckthdr() const { return d_pckthdr; }

	// give up on using libpcap's buffer and copy packet to local buffer
	void copy_data();

	void add_layer(layer_type, const u_char *begin, const u_char *end);

	void set_userdata(void *userdata) { d_userdata = userdata; }
	void *userdata() const { return d_userdata; }
protected:
	void parse_next_ethertype(uint16_t ethertype, const u_char *next, const u_char *end, const char *curname);
	void parse_next_ip_protocol(uint8_t ethertype, const u_char *next, const u_char *end, const char *curname);

	struct pcap_pkthdr d_pckthdr; // contains ts/caplen/len

	u_char *d_pcap_buf; // only initialised if this packet ever needed local storage
	const u_char *d_pcap; // points to the data, either to d_pcap_buf, or to external buffer
	uint32_t d_pcap_bufsize; // number of allocated bytes in d_pcap_buf
	uint32_t d_pcap_size; // at least caplen, number of valid bytes at *d_pcap

	// set to false on release, so pcap_reader can track if someone is still using libpcap's copy of the packet
	bool *d_still_must_copy_data;

	uint32_t d_layercount;
	layer_t d_layers[MAX_LAYERS];

	void *d_userdata;
#ifdef DEBUG
	int d_is_initialised;
#endif
};

inline layer_t *packet_t::layer(int n)
{
	if (n < 0)
		return (-n <= (int)d_layercount ? &d_layers[d_layercount+n] : NULL);
	else
		return (n < (int)d_layercount ? &d_layers[n] : NULL);
}

inline const layer_t *packet_t::next(const layer_t *layer) const // move away from ethernet
{
	assert(layer >= d_layers && layer <= d_layers + d_layercount - 1);
	return (layer == d_layers + d_layercount - 1 ? NULL : layer + 1);
}

inline const layer_t *packet_t::prev(const layer_t *layer) const // move towards ethernet
{
	assert(layer >= d_layers && layer <= d_layers + d_layercount - 1);
	return (layer == d_layers ? NULL : layer - 1);
}

inline const layer_t *packet_t::layer(int n) const
{
	return const_cast<packet_t *>(this)->layer(n);
}

std::ostream &operator <<(std::ostream &os, const packet_t &p);

#endif // __REASS_PACKET_H__

