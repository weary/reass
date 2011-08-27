#ifndef __REASS_PACKET_H__
#define __REASS_PACKET_H__

#include <pcap.h>
#include <fstream>
#include <vector>
#include <string.h>

enum layer_types {
 	layer_ethernet, // ether_header
 	layer_ipv4, // iphdr
 	layer_tcp, // tcphdr
	layer_data
};
struct layer_t
{
	layer_types type;
	const u_char *begin;
	const u_char *end;
	size_t size() const { return end-begin; }
};
std::ostream &operator <<(std::ostream &os, const layer_t &l);

struct packet_t
{
	packet_t() { }
	~packet_t() { }

	void set(int linktype, const struct pcap_pkthdr *hdr, const u_char *data);

	void reset()
	{
		::memset(d_pcap.data(), 'X', d_pcap.size());
		::memset(d_layers.data(), 'X', d_layers.size()*sizeof(layer_t));
	}

	void parse_ethernet(u_char *begin, u_char *end);
	void parse_ipv4(u_char *begin, u_char *end);
	void parse_tcp(u_char *begin, u_char *end);

	void dump(std::ostream &os) const;

protected:
	void add_layer(layer_types, u_char *begin, u_char *end);

	struct timeval d_ts;
	uint32_t d_caplen, d_len, d_layercount;
	std::vector<u_char> d_pcap; // contains at least caplen bytes
	std::vector<layer_t> d_layers;
};

std::ostream &operator <<(std::ostream &os, const packet_t &p);

#endif // __REASS_PACKET_H__

