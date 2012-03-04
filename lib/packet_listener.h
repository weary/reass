/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PACKET_LISTENER_H__
#define __REASS_PACKET_LISTENER_H__

#include "packet.h"

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

	// packet without known stream (ie, not tcp or udp)
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
};

#endif // __REASS_PACKET_LISTENER_H__
