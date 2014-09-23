#ifndef __REASS_PACKET_ENTRYPOINT_H__
#define __REASS_PACKET_ENTRYPOINT_H__

#include "reass/packet_listener.h"
#include "reass/free_list.h"
#include "reass/config.h"
#include <string>


struct tcp_reassembler_t;
struct udp_reassembler_t;


struct packet_entrypoint_t : private free_list_container_t<packet_t>
{
	packet_entrypoint_t(packet_listener_t *listener = NULL,
			bool enable_tcp = true, bool enable_udp = true);
	~packet_entrypoint_t();

	void set_linktype(int ltype) { d_linktype = ltype; }
	int linktype() const { return d_linktype; }

	// flush buffers in reassemblers
	void flush();

	// make sure to call set_linktype before handle_packet
	void handle_packet(const struct pcap_pkthdr *hdr, const u_char *data);

	uint64_t packets_seen() const { return d_packetnr; }
	void reset_packetcounter(uint64_t newval = 0) { d_packetnr = newval; }

protected:
	int d_linktype;
	packet_listener_t *d_listener;
	uint64_t d_packetnr;

	tcp_reassembler_t *d_tcp_reassembler;
	udp_reassembler_t *d_udp_reassembler;
};

#endif // __REASS_PACKET_ENTRYPOINT_H__
