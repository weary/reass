#include <string>
#include <string.h>
#include <iostream>
#include "shared/misc.h"
#include "packet.h"
#include "packet_listener.h"
#include "pcap_reader.h"

class packet_listener_t;


class tcp_stream_t
{
};

class udp_stream_t
{
};

class my_packet_listener_t : public packet_listener_t
{
	void accept(packet_t *packet)
	{
		std::cout << *packet << "\n";
		packet->release(); // done with packet
	}

	void accept_tcp(packet_t *packet, tcp_stream_t *stream)
	{
		std::cout << "TCP: " << *packet << "\n";
		packet->release(); // done with packet
	}

	void accept_udp(packet_t *packet, udp_stream_t *stream)
	{
		std::cout << "UDP: " << *packet << "\n";
		packet->release(); // done with packet
	}

	void accept_error(packet_t *packet, const char *error)
	{
		std::cout << "ERROR: " << *packet << ": " << error << "\n";
		exit(-1);
		packet->release(); // done with packet
	}
};

int main(int arcg, char *argv[])
	try
{
	my_packet_listener_t listener;
	pcap_reader_t reader("/home/weary/Desktop/testdata.pcap", &listener);
	//pcap_reader_t reader("/home/weary/Desktop/testdata_large.pcap", &listener);
	reader.read_packets();


}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

