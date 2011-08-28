/*
 * Copyright 2011 Hylke Vellinga
 */


#include "uint128.h"

struct tcp_stream_t
{
 	// packet only used to initialise src/dst, packet not added
	tcp_stream_t(packet_t *packet);
	~tcp_stream_t();

	uint128_t d_src_ip;
	uint128_t d_dst_ip;
	uint16_t d_src_port;
	uint16_t d_dst_port;

	struct timeval d_last_activity;

	void add(packet_t *packet);
};

struct tcp_reassembler_t
{
	tcp_reassembler_t(packet_listener_t *listener) :
		d_listener(listener)
	{
	}

	void process(packet_t *packet)
	{
		d_listener->accept_tcp(packet, NULL);
	}

protected:
	packet_listener_t *d_listener;
};
