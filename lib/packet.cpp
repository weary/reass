/*
 * Copyright 2011 Hylke Vellinga
 */

#define __STDC_FORMAT_MACROS // for PRIu64

#include "reass/packet.h"
#include "reass/helpers/misc.h"
#include <net/ethernet.h>
#include <net/if_ppp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <pcap/sll.h>
#include <inttypes.h>

packet_t::packet_t(packet_t *&free_head) :
	free_list_member_t<packet_t>(free_head),
	d_pcap_buf(NULL), d_pcap_bufsize(0)
#ifdef DEBUG
	,d_is_initialised(0)
#endif
{
}

packet_t::~packet_t()
{
	if (d_pcap_buf) { delete[] d_pcap_buf; d_pcap_buf = NULL; }
}

void packet_t::init(
		int linktype,
		const struct pcap_pkthdr *hdr,
		const u_char *data,
		bool *still_must_copy_data)
{
	d_pckthdr = *hdr;
	d_layercount = 0;
	const bpf_u_int32 caplen = hdr->caplen;
	d_pcap = data;
	d_pcap_size = caplen;
	d_userdata = NULL;
#ifdef DEBUG
	d_is_initialised = 1;
#endif
	d_still_must_copy_data = still_must_copy_data;
	if (!still_must_copy_data)
		copy_data();

	switch(linktype)
	{
		case(DLT_EN10MB):
			parse_ethernet(d_pcap, d_pcap + caplen);
			break;
		case(DLT_LINUX_SLL):
			parse_cooked(d_pcap, d_pcap + caplen);
			break;
		case(DLT_RAW):
			if (caplen > 0 && (d_pcap[0] >> 4) == 6)
				parse_ipv6(d_pcap, d_pcap + caplen);
			else
				parse_ipv4(d_pcap, d_pcap + caplen);
			break;
		case(18): // FIXME 18 only defined for openbsd, while this seems to be another DLT_RAW
			parse_ipv4(d_pcap, d_pcap + caplen);
			break;
		default:
			throw format_exception("unsupported linktype %d", linktype);
	}
}

static void rebase_ptr(const u_char *&p, const u_char *oldbuf, const u_char *newbuf)
{
	assert(p>=oldbuf);
	p = newbuf + (p-oldbuf);
}

void packet_t::copy_data()
{
	assert(d_pcap != d_pcap_buf);
	const bpf_u_int32 caplen = d_pckthdr.caplen;
	if (d_pcap_bufsize < caplen) // do we have enough space ready?
	{
		delete[] d_pcap_buf;
		d_pcap_buf = new u_char[caplen];
		d_pcap_bufsize = caplen;
	}
	for (unsigned n=0; n<d_layercount; ++n)
	{ // adust layers to new pointers
		rebase_ptr(d_layers[n].d_begin, d_pcap, d_pcap_buf);
		rebase_ptr(d_layers[n].d_end, d_pcap, d_pcap_buf);
	}

	// memcpy
	u_char *d = d_pcap_buf;
	const u_char *s = d_pcap;
	for (unsigned n=0; n<caplen; ++n)
		d[n] = s[n];

	d_pcap = d_pcap_buf;
	d_still_must_copy_data = NULL;
}

void packet_t::add_layer(layer_type type, const u_char *begin, const u_char *end)
{
	if (d_layercount >= MAX_LAYERS)
		throw format_exception("max layers reached");
	d_layers[d_layercount].set(begin, end, type);
	++d_layercount;
}

struct logical_link_layer_t : public unknown_layer_t
{
	logical_link_layer_t(uint32_t next, const char *cur) throw() :
		unknown_layer_t(next, cur) {}

	virtual const char* what() const throw()
	{
		static char buf[256];
		sprintf(buf, "unsupported logical link layer 0x%x in %s header", d_next, d_cur);
		return buf;
	}
};

void packet_t::parse_next_ethertype(uint16_t ethertype,
		const u_char *next, const u_char *end, const char *curname)
{
	if (ethertype <= 1500) // all these mean logical-link control layer
		throw logical_link_layer_t(ethertype, curname);
	else if (ethertype <= 1536)
		throw format_exception("invalid protocol 0x%x in %s header (should not have this value)", ethertype, curname);

	switch(ethertype)
	{
		case(ETHERTYPE_IP): parse_ipv4(next, end); break;
		case(ETHERTYPE_IPV6): parse_ipv6(next, end); break;
		case(ETHERTYPE_VLAN): parse_vlan(next, end); break;
		case(ETH_P_PPP_SES): parse_pppoe(next, end); break;

		default:
			throw unknown_layer_t(ethertype, curname);
	}
}

void packet_t::parse_cooked(const u_char *begin, const u_char *end)
{
	if ((size_t)(end-begin) < sizeof(sll_header))
		throw format_exception("packet has %d bytes, but need %d for cooked header",
				end-begin, sizeof(sll_header));

	const sll_header &hdr = reinterpret_cast<const sll_header &>(*begin);

	add_layer(layer_cooked, begin, end);

	const u_char *next = begin + sizeof(hdr);
	parse_next_ethertype(ntohs(hdr.sll_protocol), next, end, "cooked");
}

void packet_t::parse_ethernet(const u_char *begin, const u_char *end)
{
	if ((size_t)(end-begin) < sizeof(ether_header))
		throw format_exception("packet has %d bytes, but need %d for ethernet header",
				end-begin, sizeof(ether_header));

	const ether_header &hdr = reinterpret_cast<const ether_header &>(*begin);

	add_layer(layer_ethernet, begin, end);

	const u_char *next = begin + sizeof(hdr);
	parse_next_ethertype(ntohs(hdr.ether_type), next, end, "ether");
}

void packet_t::parse_vlan(const u_char *begin, const u_char *end)
{
	const size_t vlan_size = 4;
	if ((size_t)(end-begin) < vlan_size)
		throw format_exception("packet has %d bytes, but need %d for vlan header",
				end-begin, vlan_size);

	const uint16_t *hdr = reinterpret_cast<const uint16_t *>(begin);

	const u_char *next = begin + vlan_size;
	parse_next_ethertype(ntohs(hdr[1]), next, end, "vlan");
}

void packet_t::parse_pppoe(const u_char *begin, const u_char *end)
{
	const size_t pppoe_size = 8; //PPPOE 6, PPP 2
	if ((size_t)(end-begin) < pppoe_size)
		throw format_exception("packet has %d bytes, but need %d for pppoe header",
				end-begin, pppoe_size);

	add_layer(layer_pppoe, begin, end);
	const uint16_t *hdr = reinterpret_cast<const uint16_t *>(begin + 6);
	const u_char *next = begin + pppoe_size;
	switch(ntohs(*hdr))
	{
		case(PPP_IP):
			parse_ipv4(next,end);
			break;
		default:
			throw unknown_layer_t(ntohs(*hdr), "ppp");
	}
}

void packet_t::parse_next_ip_protocol(uint8_t protocol, const u_char *next, const u_char *nend, const char *curname)
{
	switch(protocol)
	{
		case(IPPROTO_TCP): parse_tcp(next, nend); break;
		case(IPPROTO_UDP): parse_udp(next, nend); break;
		case(IPPROTO_IPV6): parse_ipv6(next,nend); break;

		default:
			throw unknown_layer_t(protocol, curname);
	}
}

void packet_t::parse_ipv4(const u_char *begin, const u_char *end)
{
	if (begin == end)
		throw format_exception("empty ipv4 header");

	const ip &hdr = reinterpret_cast<const ip &>(*begin);
	if (hdr.ip_v != 4)
		throw format_exception("expected ip version 4, got %d", hdr.ip_v);

	size_t size = end-begin;
	if (size < sizeof(ip) || size < (size_t)hdr.ip_hl*4)
		throw format_exception("packet has %d bytes, but need %d for ip header",
				size, std::max<size_t>(sizeof(ip), hdr.ip_hl*4));
	size_t hdrsize = hdr.ip_hl*4;
	int payload = htons(hdr.ip_len) - hdrsize;
	if (payload <= 0)
		throw format_exception("no content in ip-packet. expected next layer");
	assert(sizeof(ip) <= hdrsize);
	add_layer(layer_ipv4, begin, end);

	const uint16_t fragment_offset_mask = (1<<13)-1;
	uint16_t frag_off = 8*(htons(hdr.ip_off) & fragment_offset_mask);
	bool more_fragments = (htons(hdr.ip_off) >> 13) & 1;
	if (more_fragments || frag_off)
		throw format_exception("fragments not supported");

	const u_char *next = begin + hdr.ip_hl*4;
	const u_char *nend = std::min<const u_char *>(end, next + payload);
	parse_next_ip_protocol(hdr.ip_p, next, nend, "ip");
}

void packet_t::parse_ipv6(const u_char *begin, const u_char *end)
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
	const u_char *next = begin + sizeof(ip6_hdr);
	if (next + payloadlen > end)
		throw format_exception("missing bytes from ipv6 field, have %d, need %d", end - next, payloadlen);

	parse_next_ip_protocol(hdr.ip6_nxt, next, next + payloadlen, "ipv6");
}

void packet_t::parse_tcp(const u_char *begin, const u_char *end)
{
	const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*begin);
	size_t size = end-begin;
	if (size < sizeof(tcphdr))
		throw format_exception("packet has %d bytes, but need %d for tcp header",
				size, sizeof(tcphdr));
	if (size < (size_t)hdr.th_off*4)
		throw format_exception("packet has %d bytes, but need %d for tcp header",
				size, hdr.th_off*4);
	add_layer(layer_tcp, begin, end);
	const u_char *data = begin + hdr.th_off*4;
	if (data < end)
		add_layer(layer_data, data, end);
};

void packet_t::parse_udp(const u_char *begin, const u_char *end)
{
	const udphdr &hdr = reinterpret_cast<const udphdr &>(*begin);
	size_t size = end-begin;
	if (size < sizeof(udphdr))
		throw format_exception("packet has %d bytes, but need %d for udp header",
				size, sizeof(udphdr));
	int payload = htons(hdr.uh_ulen) - sizeof(udphdr);
	const u_char *next = begin + sizeof(udphdr);
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
		case(layer_cooked): os << "cooked"; break;
		case(layer_ipv4):
			{
				const ip &hdr = reinterpret_cast<const ip &>(*l.data());
				os << "ipv4[";
				ipv4addr(os, &hdr.ip_src);
				os << "-";
				ipv4addr(os, &hdr.ip_dst);
				os << "]";
			}
			break;
		case(layer_ipv6): os << "ipv6"; break;
		case(layer_tcp):
			{
				const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*l.data());
				os << "tcp[" << htons(hdr.th_sport) << "-" << htons(hdr.th_dport);
				if (1)
				{
					char buf[256];
					sprintf(buf, " seq=%08x ack=%08x", htonl(hdr.th_seq), htonl(hdr.th_ack));
					os << buf;
				}
				if (1)
				{
					if (hdr.th_flags & 0x3F)
						os << ' ';

					if (hdr.th_flags & TH_URG) os << 'U';
					if (hdr.th_flags & TH_ACK) os << 'A';
					if (hdr.th_flags & TH_PUSH) os << 'P';
					if (hdr.th_flags & TH_RST) os << 'R';
					if (hdr.th_flags & TH_SYN) os << 'S';
					if (hdr.th_flags & TH_FIN) os << 'F';
				}
				os << ']';
			}
			break;
		case(layer_udp):
			{
				const udphdr &hdr = reinterpret_cast<const udphdr &>(*l.data());
				os << "udp[" << htons(hdr.uh_sport) << "-" << htons(hdr.uh_dport) << ']';
			}
			break;
		case(layer_pppoe): os << "pppoe"; break;
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
	struct timeval ts = d_pckthdr.ts;
	bpf_u_int32 len = d_pckthdr.len;
	bpf_u_int32 caplen = d_pckthdr.caplen;
	sprintf(buf, "[%d.%06d %4d",
			(unsigned)ts.tv_sec, (unsigned)ts.tv_usec, caplen);
	os << buf;
	if (caplen != len)
		os << '/' << len;
	os << "] { ";
	for (unsigned n=0; n<d_layercount; ++n)
		os << d_layers[n] << ' ';
	os << '}';
}
