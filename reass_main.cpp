#include "shared/misc.h"
#include "packet.h"
#include "packet_listener.h"
#include "pcap_reader.h"
#include "tcp_reassembler.h"
#include <string>
#include <string.h>
#include <iostream>

class packet_listener_t;


struct stream_t
{
	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		if (packet)
		{
			layer_t *toplayer = packet->layer(-1);
			if (!toplayer || toplayer->type() != layer_data)
				std::cout << "TCP " << *stream << " got empty packet\n";
			else
			{
				d_data.append(toplayer->begin(), toplayer->end());
				std::cout << "TCP " << *stream << " got packet with " << toplayer->size() << " bytes, now " << d_data.size() << " total\n";
			}
			if (stream->closed() && !d_data.empty())
			{
				std::cout << "CLOSED\n";
				//std::cout << d_data << "\n";
				std::ofstream f(to_str(*stream));
				f << d_data;
				d_data.clear();
			}
			packet->release();
		}
		else
		{
			std::cout << "TCP " << *stream << " closed, got " << d_data.size() << " bytes data\n";
		}
	}

	std::string d_data;
};

class my_packet_listener_t : public packet_listener_t
{
	void accept(packet_t *packet)
	{
		std::cout << *packet << "\n";
		packet->release(); // done with packet
	}

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		stream_t *user = reinterpret_cast<stream_t *>(stream->userdata());
		if (!user)
		{
			user = new stream_t();
			stream->set_userdata(user);
		}
		assert(user);
		user->accept_tcp(packet, packetloss, stream);
		if (!packet)
			delete user;
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

int main(int argc, char *argv[])
	try
{
	if (argc != 2)
		throw format_exception("need one argument, a pcap file");

	my_packet_listener_t listener;
	pcap_reader_t reader(argv[1], &listener);
	reader.read_packets();


}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

