#include "shared/misc.h"
#include "packet.h"
#include "packet_listener.h"
#include "pcap_reader.h"
#include "pcap_writer.h"
#include "tcp_reassembler.h"
#include <string>
#include <string.h>
#include <iostream>

class packet_listener_t;


class my_packet_listener_t : public packet_listener_t
{
public:
	pcap_writer_t *d_writer;
	my_packet_listener_t() : d_writer(NULL) {}
	~my_packet_listener_t() { delete d_writer; d_writer = NULL; }

	void open_output(const std::string &fname, int linktype, int snaplen)
	{
		delete d_writer;
		d_writer = new pcap_writer_t(fname, linktype, snaplen);
		std::cout << "writing to '" << fname << "'\n";
	}

	void accept(packet_t *packet)
	{
		assert(packet);
		(*d_writer) << packet;
		packet->release(); // done with packet
	}

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		if (packet)
		{
			(*d_writer) << packet;
			packet->release(); // done with packet
		}
	}

	void accept_udp(packet_t *packet, udp_stream_t *stream)
	{
		packet->release(); // done with packet
	}

	void accept_error(packet_t *packet, const char *error)
	{
		std::cout << "ERROR: " << *packet << ": " << error << "\n";
		exit(-1);
		packet->release(); // done with packet
	}
};

int main(int argc, char *argv[])
	try
{
	if (argc != 2)
		throw format_exception("need one argument, a pcap file");

	my_packet_listener_t listener;
	pcap_reader_t reader(argv[1], &listener);
	listener.open_output("blub.pcap", reader.linktype(), reader.snaplen());
	reader.read_packets();


}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

