#include "reass/packet.h"
#include "reass/packet_listener.h"
#include "reass/pcap_reader.h"
#include "reass/pcap_writer.h"
#include "reass/tcp_reassembler.h"
#include <string>
#include <string.h>
#include <iostream>
#include <boost/foreach.hpp>

class my_packet_listener_t : public packet_listener_t
{
	void accept_error(packet_t *packet, const char *error)
	{
		std::cout << "ERROR: " << *packet << ": " << error << "\n";
		packet->release(); // done with packet
	}
};

void printhelp(const char *argv0)
{
	printf("\nreassemble tcp streams and discard\n\n");
	printf("%s [--live <device>] [--bpf <bpf>] [pcaps]\n", basename(argv0));
}

int main(int argc, char *argv[])
	try
{
	for (int n=1; n<argc; ++n)
	{
		if (strcmp(argv[n], "-h")==0 or strcmp(argv[n], "--help") == 0)
		{
			printf("%s pcaps\n", basename(argv[0]));
			return -1;
		}
	}

	my_packet_listener_t listener;
	pcap_reader_t reader(&listener);
	for (int n=1; n<argc; ++n)
		reader.read_file(argv[n]);
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

