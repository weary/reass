#include "packet.h"
#include "net/ethernet.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "shared/misc.h"

void packet_t::set(int linktype, const struct pcap_pkthdr *hdr, const u_char *data)
{
	d_ts = hdr->ts;
	d_caplen = hdr->caplen;
	d_len = hdr->len;
	d_layercount = 0;
	if (d_pcap.size() < hdr->caplen)
		d_pcap.resize(hdr->caplen);
	::memcpy(d_pcap.data(), data, d_caplen);

	if (linktype == DLT_EN10MB)
		parse_ethernet(d_pcap.data(), d_pcap.data() + d_caplen);
}

void packet_t::add_layer(layer_types type, u_char *begin, u_char *end)
{
	if (d_layercount+1 > d_layers.size())
		d_layers.resize(d_layercount+2);
	layer_t &lay = d_layers[d_layercount];
	lay.type = type;
	lay.begin = begin;
	lay.end = end;
	++d_layercount;
}

void packet_t::parse_ethernet(u_char *begin, u_char *end)
{
	if ((size_t)(end-begin) < sizeof(ether_header))
		throw format_exception("packet has %d bytes, but need %d for ethernet header",
				end-begin, sizeof(ether_header));

	const ether_header &hdr = reinterpret_cast<const ether_header &>(*begin);

	add_layer(layer_ethernet, begin, end);

	if (ntohs(hdr.ether_type) == ETHERTYPE_IP)
		parse_ipv4(begin + sizeof(hdr), end);
	else
		throw format_exception("invalid ether_type %d in ethernet header", hdr.ether_type);
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
	assert(sizeof(iphdr) <= (size_t)hdr.ihl*4);
	add_layer(layer_ipv4, begin, end);

	if (hdr.protocol == IPPROTO_TCP)
		parse_tcp(begin + hdr.ihl*4, end);
	else
		throw format_exception("unsupported protocol %d in ip header", hdr.protocol);
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
	add_layer(layer_data, begin + hdr.doff*4, end);
};

std::ostream &operator <<(std::ostream &os, const packet_t &p)
{
	p.dump(os);
	return os;
}

static void ipv4addr(std::ostream &os, const void *ip /* network order */)
{
	const uint8_t *t = reinterpret_cast<const uint8_t *>(ip);
	os << (int)t[0] << '.' << (int)t[1] << '.' << (int)t[2] << '.' << (int)t[3];
};

std::ostream &operator <<(std::ostream &os, const layer_t &l)
{
	switch(l.type)
	{
		case(layer_ethernet): os << "eth"; break;
		case(layer_ipv4):
			{
				const iphdr &hdr = reinterpret_cast<const iphdr &>(*l.begin);
				os << "ipv4[";
				ipv4addr(os, &hdr.saddr);
				os << "-";
				ipv4addr(os, &hdr.daddr);
				os << "]";
			}
			break;
		case(layer_tcp):
			{
				const tcphdr &hdr = reinterpret_cast<const tcphdr &>(*l.begin);
				os << "tcp[" << htons(hdr.source) << "-" << htons(hdr.dest);
				if (1)
				{
					char buf[256];
					sprintf(buf, " seq=%04x ack=%04x", htons(hdr.seq), htons(hdr.ack_seq));
					os << buf;
				}
				os << ']';
			}
			break;
		case(layer_data):
			{
				os << "data[" << l.size() << ']';
			}
	}
	return os;
}

void packet_t::dump(std::ostream &os) const
{
	char buf[256];
	sprintf(buf, "[%d.%06d %d", (unsigned)d_ts.tv_sec, (unsigned)d_ts.tv_usec, d_caplen);
	os << buf;
	if (d_caplen != d_len)
		os << '/' << d_len;
	os << "] { ";
	for (unsigned n=0; n<d_layercount; ++n)
		os << d_layers[n] << ' ';
	os << '}';
}

