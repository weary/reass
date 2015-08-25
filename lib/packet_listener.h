/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PACKET_LISTENER_H__
#define __REASS_PACKET_LISTENER_H__

#include "reass/packet.h"
#include "reass/helpers/misc.h"

struct tcp_stream_t;
struct udp_stream_t;

class packet_listener_t
{
public:
	virtual ~packet_listener_t() {}

	// called when a new pcap file is opened or when live capture is started
	// name is the device name (for live capture) or pcap-filename
	virtual void begin_capture(const std::string &name, int linktype, int snaplen)
	{}

	// called before reassembly, use for initialising packet-userdata
	virtual void new_packet(packet_t *packet, uint64_t packetnr)
	{
		// note, do NOT release packet in here, will go to reassembly
		// after return
	}

	// packet without known stream (ie, not tcp or udp, or reassembly disabled)
	virtual void accept(packet_t *packet)
	{
		packet->release(); // done with packet
	}

	// packet in tcp stream. will be called with NULL as packet when stream is cleaned up
	// note that stream can be considered closed before that, use tcp_stream_t::closed() (fin/rst packet has been accepted)
	virtual void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		if (packet)
			packet->release(); // done with packet
	}

	// packet in udp stream
	virtual void accept_udp(packet_t *packet, udp_stream_t *stream)
	{
		if (packet)
			packet->release(); // done with packet
	}

	// parsing failed on packet
	virtual void accept_error(packet_t *packet, const char *error)
	{
		packet->release(); // done with packet
	}

	// saw a fin or rst in a tcp stream, called at most once per stream
	virtual void end_of_stream(tcp_stream_t *stream)
	{
	}

	// called with extra information about where the packet is in the
	// engine. Make sure to also override all other methods in this
	// class, debug_packet is only called for events not reported by
	// other functions.
	// compiler can optimize function away in release builds (not virtual)
#ifdef DEBUG
	virtual
#else
	inline
#endif
		void debug_packet(packet_t *packet, const char *fmt, ...)
		PRINTFCHECK(3, 4)
	{
		// do NOT release here
	}
};

#endif // __REASS_PACKET_LISTENER_H__
