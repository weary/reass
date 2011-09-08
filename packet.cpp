/*
 * Copyright 2011 Hylke Vellinga
 */

#define __STDC_FORMAT_MACROS // for PRIu64

#include "packet.h"
#include "net/ethernet.h"
#include "netinet/ip.h"
#include "netinet/ip6.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "shared/misc.h"
#include <inttypes.h>

packet_t::packet_t(packet_t *&free_head) :
	free_list_member_t<packet_t>(free_head)
#ifdef DEBUG
	,d_is_initialised(0)
#endif
{
}

packet_t::~packet_t()
{
}

void packet_t::init(uint64_t packetnr, int linktype, const struct pcap_pkthdr *hdr, const u_char *data)
{
	d_packetnr = packetnr;
	d_ts = hdr->ts;
	d_caplen = hdr->caplen;
	d_len = hdr->len;
	d_layercount = 0;
#ifdef DEBUG
	d_is_initialised = 1;
#endif
	if (d_pcap.size() < hdr->caplen)
		d_pcap.resize(hdr->caplen);
	::memcpy(d_pcap.data(), data, d_caplen);

	if (linktype == DLT_EN10MB)
		parse_ethernet(d_pcap.data(), d_pcap.data() + d_caplen);
}

void packet_t::add_layer(layer_type type, const u_char *begin, const u_char *end)
{
	if (d_layercount >= MAX_LAYERS)
		throw format_exception("max layers reached");
	d_layers[d_layercount] = layer_t(begin, end, type);
	++d_layercount;
}

void packet_t::parse_ethernet(u_char *begin, u_char *end)
{
	if ((size_t)(end-begin) < sizeof(ether_header))
		throw format_exception("packet has %d bytes, but need %d for ethernet header",
				end-begin, sizeof(ether_header));

	const ether_header &hdr = reinterpret_cast<const ether_header &>(*begin);

	add_layer(layer_ethernet, begin, end);

	u_char *next = begin + sizeof(hdr);
	switch(ntohs(hdr.ether_type))
	{
		case(ETHERTYPE_IP): parse_ipv4(next, end); break;
		case(ETHERTYPE_IPV6): parse_ipv6(next, end); break;
		case(ETHERTYPE_ARP): /* arp */ break;
		case(0x88CC): /* LLDP */ break;
		default:
			throw format_exception("invalid ether_type 0x%x in ethernet header", ntohs(hdr.ether_type));
	}
}

void packet_t::parse_ipv4(u_char *begin, u_char *end)
{
	if (begin == end)
		throw format_exception("empty ipv4 header");

	const iphdr &hdr = reinterpret_cast<const iphdr &>(*begin);
	if (hdr.version != 4)
		throw format_exception("expected ip version 4, got %d", hdr.version);

	size_t size = end-begin;
	if (size < sizeof(iphdr) || size < (size_t)hdr.ihl*4)
		throw format_exception("packet has %d bytes, but need %d for ip header",
				size, std::max<size_t>(sizeof(iphdr), hdr.ihl*4));
	size_t hdrsize = hdr.ihl*4;
	int payload = htons(hdr.tot_len) - hdrsize;
	if (payload <= 0)
		throw format_exception("no content in ip-packet. expected next layer");
	assert(sizeof(iphdr) <= hdrsize);
	add_layer(layer_ipv4, begin, end);

	// FIXME: fragments

	u_char *next = begin + hdr.ihl*4;
	u_char *nend = std::min<u_char *>(end, next + payload);
	switch(hdr.protocol)
	{
		case(IPPROTO_TCP): parse_tcp(next, nend); break;
		case(IPPROTO_UDP): parse_udp(next, nend); break;
		case(IPPROTO_IGMP): break; // internet group management protocol
		case(IPPROTO_ICMP): add_layer(layer_icmp, next, nend); break;
		default:
			throw format_exception("unsupported protocol %d in ip header", hdr.protocol);
	}
}

void packet_t::parse_ipv6(u_char *begin, u_char *end)
{
	if (begin == end)
		throw format_exception("empty ipv6 header");

	const ip6_hdr &hdr = reinterpret_cast<const ip6_hdr &>(*begin);
	int version = (*begin) >> 4;
	if (version != 6)
		throw format_exception("expected ip version 6, got %d", version);

	size_t size = end-begin;
	if (size < sizeof(ip6_hdr))
		throw format_exception("packet has %d bytes, but need %d for ip header",
				size, sizeof(ip6_hdr));
	add_layer(layer_ipv6, begin, end);

	uint16_t payloadlen = ntohs(hdr.ip6_ctlun.ip6_un1.ip6_un1_plen);
	u_char *next = begin + sizeof(ip6_hdr);
	if (next + payloadlen > end)
		throw format_exception("missing bytes from ipv6 field, have %d, need %d", end - next, payloadlen);
#if 0
	if (hdr.protocol == IPPROTO_TCP)
		parse_tcp(next, next + payloadlen);
	else
		throw format_exception("unsupported protocol %d in ipv6 header", hdr.protocol);
#endif
}

void packet_t::parse_tcp(u_char *begin, u_char *end)
{
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*begin);
	size_t size = end-begin;
	if (size < sizeof(tcphdr))
		throw format_exception("packet has %d bytes, but need %d for tcp header",
				size, sizeof(tcphdr));
	if (size < (size_t)hdr.doff*4)
		throw format_exception("packet has %d bytes, but need %d for tcp header",
				size, hdr.doff*4);
	add_layer(layer_tcp, begin, end);
	u_char *data = begin + hdr.doff*4;
	if (data < end)
		add_layer(layer_data, data, end);
};

void packet_t::parse_udp(u_char *begin, u_char *end)
{
	const udphdr &hdr = reinterpret_cast<const udphdr &>(*begin);
	size_t size = end-begin;
	if (size < sizeof(udphdr))
		throw format_exception("packet has %d bytes, but need %d for udp header",
				size, sizeof(udphdr));
	int payload = htons(hdr.len) - sizeof(udphdr);
	u_char *next = begin + sizeof(udphdr);
	add_layer(layer_udp, begin, end);
	if (end-next < payload) payload = end-next;
	if (payload > 0)
		add_layer(layer_data, next, next + payload);
}

std::ostream &operator <<(std::ostream &os, const packet_t &p)
{
	p.print(os);
	return os;
}

static void ipv4addr(std::ostream &os, const void *ip /* network order */)
{
	const uint8_t *t = reinterpret_cast<const uint8_t *>(ip);
	os << (int)t[0] << '.' << (int)t[1] << '.' << (int)t[2] << '.' << (int)t[3];
};

std::ostream &operator <<(std::ostream &os, const layer_t &l)
{
	switch(l.type())
	{
		case(layer_ethernet): os << "eth"; break;
		case(layer_ipv4):
			{
				const iphdr &hdr = reinterpret_cast<const iphdr &>(*l.data());
				os << "ipv4[";
				ipv4addr(os, &hdr.saddr);
				os << "-";
				ipv4addr(os, &hdr.daddr);
				os << "]";
			}
			break;
		case(layer_ipv6): os << "ipv6"; break;
		case(layer_tcp):
			{
				const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*l.data());
				os << "tcp[" << htons(hdr.source) << "-" << htons(hdr.dest);
				if (1)
				{
					char buf[256];
					sprintf(buf, " seq=%08x ack=%08x", htonl(hdr.seq), htonl(hdr.ack_seq));
					os << buf;
				}
				if (1)
				{
					if (hdr.urg || hdr.ack || hdr.psh ||
							hdr.rst || hdr.syn || hdr.fin)
						os << ' ';

					if (hdr.urg) os << 'U';
					if (hdr.ack) os << 'A';
					if (hdr.psh) os << 'P';
					if (hdr.rst) os << 'R';
					if (hdr.syn) os << 'S';
					if (hdr.fin) os << 'F';
				}
				os << ']';
			}
			break;
		case(layer_udp):
			{
				const udphdr &hdr = reinterpret_cast<const udphdr &>(*l.data());
				os << "udp[" << htons(hdr.source) << "-" << htons(hdr.dest) << ']';
			}
			break;
		case(layer_icmp): os << "icmp"; break;
		case(layer_data):
			{
				os << "data[" << l.size() << ']';
			}
	}
	return os;
}

void packet_t::print(std::ostream &os) const
{
	char buf[256];
	sprintf(buf, "[%4"PRIu64" %d.%06d %4d", d_packetnr, (unsigned)d_ts.tv_sec, (unsigned)d_ts.tv_usec, d_caplen);
	os << buf;
	if (d_caplen != d_len)
		os << '/' << d_len;
	os << "] { ";
	for (unsigned n=0; n<d_layercount; ++n)
		os << d_layers[n] << ' ';
	os << '}';
}

