/*
 * Copyright 2011 Hylke Vellinga
 */


#include "reass/packet_entrypoint.h"
#include "reass/packet_listener.h"
#include "reass/tcp_reassembler.h"
#include "reass/udp_reassembler.h"
#include "reass/config.h"
#include "reass/helpers/misc.h"


packet_entrypoint_t::packet_entrypoint_t(
		packet_listener_t *listener,
		bool enable_tcp, bool enable_udp) :
	free_list_container_t<packet_t>(0),
	d_linktype(-1),
	d_listener(listener), d_packetnr(0),
	d_tcp_reassembler(NULL), d_udp_reassembler(NULL)
{
	if (enable_tcp)
		d_tcp_reassembler = new tcp_reassembler_t(d_listener);
	if (enable_udp)
		d_udp_reassembler = new udp_reassembler_t(d_listener);
}

packet_entrypoint_t::~packet_entrypoint_t()
{
	flush();

#ifdef PRINT_STATS
	printf("saw %ld packets\n", d_packetnr);
#if !defined(NO_REUSE) and defined(DEBUG)
	printf("max %d packet_t's in use\n", objectcount());
#endif
#endif // PRINT_STATS

	delete d_tcp_reassembler; d_tcp_reassembler = NULL;
	delete d_udp_reassembler; d_udp_reassembler = NULL;
}

void packet_entrypoint_t::flush()
{
	if (d_tcp_reassembler)
		d_tcp_reassembler->flush();

	if (d_udp_reassembler)
		d_udp_reassembler->flush();
}

// called whenever libpcap has a packet
void packet_entrypoint_t::handle_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
	if (d_linktype == -1)
		throw std::runtime_error("Linktype not set. Call set_linktype before handle_packet");

	++d_packetnr;

	packet_t *packet = claim(); // get space from free list (or new if free list was empty)

	bool must_copy = true; // packet is using libpcap memory
	try
	{
		packet->init(d_linktype, hdr, data, &must_copy); // parse layers

		if (d_tcp_reassembler)
			d_tcp_reassembler->set_now(packet->ts().tv_sec);
		if (d_udp_reassembler)
			d_udp_reassembler->set_now(packet->ts().tv_sec);

		// reassemble tcp if top-layer is tcp, or tcp+data
		layer_t *top = packet->layer(-1);
		layer_t *second = packet->layer(-2);
		if (!top || !second)
			d_listener->accept(packet); // less than two layers -> get rid of it
		else if (d_tcp_reassembler && (
					top->type() == layer_tcp ||
					(top->type() == layer_data && second->type() == layer_tcp)))
			d_tcp_reassembler->process(packet);
		else if (d_udp_reassembler && (
					top->type() == layer_udp ||
					(top->type() == layer_data && second->type() == layer_udp)))
			d_udp_reassembler->process(packet);
		else // don't know. just pass on packet
			d_listener->accept(packet);
	}
	catch(const unknown_layer_t &e)
	{
#ifdef UNKNOWN_LAYER_AS_ERROR
		d_listener->accept_error(packet, e.what());
#else
		packet->release();
#endif
	}
	catch(const std::exception &e)
	{
		d_listener->accept_error(packet, e.what());
	}
	if (must_copy)
		packet->copy_data();
}

