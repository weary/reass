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

	virtual void accept(packet_t *packet)
	{
		packet->free(); // done with packet
	}

	virtual void accept_tcp(packet_t *packet, tcp_stream_t *stream)
	{
		packet->free(); // done with packet
	}

	virtual void accept_udp(packet_t *packet, udp_stream_t *stream)
	{
		packet->free(); // done with packet
	}
};

#endif // __REASS_PACKET_LISTENER_H__
