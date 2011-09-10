/*
 * Copyright 2011 Hylke Vellinga
 */


#include "pcap_reader.h"
#include "packet_listener.h"
#include "shared/misc.h"
#include "tcp_reassembler.h"

struct udp_reassembler_t
{
	udp_reassembler_t(packet_listener_t *listener) :
		d_listener(listener)
	{
	}

	void process(packet_t *packet)
	{
		d_listener->accept_udp(packet, NULL);
	}

	void flush() {}

protected:
	packet_listener_t *d_listener;
};

pcap_reader_t::pcap_reader_t(
	const std::string &fname, packet_listener_t *listener) :
	free_list_container_t<packet_t>(0),
	d_pcap(NULL), d_packetnr(0), d_listener(listener),
	d_tcp_reassembler(new tcp_reassembler_t(listener)),
	d_udp_reassembler(new udp_reassembler_t(listener))
{
	char errbuf[PCAP_ERRBUF_SIZE];
	d_pcap = pcap_open_offline(fname.c_str(), errbuf);
	if (!d_pcap)
		throw format_exception("Could not open pcap '%s', %s", fname.c_str(), errbuf);

	d_linktype = pcap_datalink(d_pcap);
}

pcap_reader_t::~pcap_reader_t()
{
	if (d_pcap)
	{
		pcap_close(d_pcap);
		d_pcap = NULL;
	}
#if !defined(NO_REUSE) and defined(DEBUG)
	printf("max %d packet_t's in use\n", objectcount());
#endif

	flush();

	delete d_tcp_reassembler;
	delete d_udp_reassembler;
}

void pcap_reader_t::flush()
{
	d_tcp_reassembler->flush();
	d_udp_reassembler->flush();
}

// called whenever libpcap has a packet
void pcap_reader_t::handle_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
	packet_t *packet = claim();

	try
	{
		packet->init(++d_packetnr, d_linktype, hdr, data);

		// reassemble tcp if top-layer is tcp, or tcp+data
		layer_t *top = packet->layer(-1);
		layer_t *second = packet->layer(-2);
		if (!top || !second)
			d_listener->accept(packet); // less than two layers -> get rid of it
		else if (top->type() == layer_tcp ||
				(top->type() == layer_data && second->type() == layer_tcp))
			d_tcp_reassembler->process(packet);
		else if (top->type() == layer_udp ||
				(top->type() == layer_data && second->type() == layer_udp))
			d_udp_reassembler->process(packet);
		else // don't know. just pass on packet
			d_listener->accept(packet);
	}
	catch(const std::exception &e)
	{
		d_listener->accept_error(packet, e.what());
	}
}

#ifdef NO_MEMBER_CALLBACK
void extra_callback_hop(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	reinterpret_cast<pcap_reader_t *>(user)->handle_packet(hdr, data);
}
#endif

void pcap_reader_t::read_packets() // read one bufferful of packets
{
	assert(d_pcap);

#ifndef NO_MEMBER_CALLBACK
	// note: don't try this at home, kids
	pcap_handler handler = reinterpret_cast<pcap_handler>(&pcap_reader_t::handle_packet);
#else
	pcap_handler handler = &extra_callback_hop;
#endif
	int r = pcap_dispatch(d_pcap, -1, handler, (u_char *)this);
	if (r == -1)
		throw format_exception("Pcap reader failed, %s", pcap_geterr(d_pcap));
	printf("got %d packets in read_packets\n", r);
}

