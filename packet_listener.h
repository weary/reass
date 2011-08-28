/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PACKET_LISTENER_H__
#define __REASS_PACKET_LISTENER_H__

#include "packet.h"

class tcp_stream_t;
class udp_stream_t;

class packet_listener_t
{
public:
	virtual ~packet_listener_t() {}

	// packet without known stream (ie, not tcp or udp)
	virtual void accept(packet_t *packet)
	{
		packet->free(); // done with packet
	}

	// packet in tcp stream
	virtual void accept_tcp(packet_t *packet, tcp_stream_t *stream)
	{
		packet->free(); // done with packet
	}

	// packet in udp stream
	virtual void accept_udp(packet_t *packet, udp_stream_t *stream)
	{
		packet->free(); // done with packet
	}

	// parsing failed on packet
	virtual void accept_error(packet_t *packet, const char *error)
	{
		packet->free(); // done with packet
	}
};

#endif // __REASS_PACKET_LISTENER_H__
