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
	stream_t(tcp_stream_t *stream) :
		d_stream(stream), d_key(to_str(*stream))
	{
#if 0
		std::cout << "TCP " << d_key << " created, ";
		std::cout << (stream->initiator() ? "initiator" : "responder") << ", ";
		if (stream->have_partner())
			std::cout << "partner = " << *stream->partner() << "\n";
		else
			std::cout << "no partner\n";
#endif
	}

	~stream_t()
	{
		//std::cout << "TCP " << d_key << " destroyed\n";
	}

	void accept_tcp(packet_t *packet, int packetloss)
	{
		if (packet)
		{
			layer_t *toplayer = packet->layer(-1);
			if (!toplayer || toplayer->type() != layer_data)
			{
				//std::cout << "TCP " << d_key << " got empty packet\n";
			}
			else
			{
				d_data.append(toplayer->begin(), toplayer->end());
				//std::cout << "TCP " << d_key << " got packet with " << toplayer->size() << " bytes, now " << d_data.size() << " total\n";
			}
			if (d_stream->closed() && !d_data.empty())
			{
				//std::cout << "TCP " << d_key << " closed\n";
				//std::ofstream f(to_str(*d_stream));
				//f << d_data;
				d_data.clear();
			}
			packet->release();
		}
		else
		{
			//std::cout << "TCP " << d_key << " finally closed, got " << d_data.size() << " bytes data\n";
		}
	}

	tcp_stream_t *d_stream; // note, not valid after accept_tcp(NULL, ..) has been called
	std::string d_key;
	std::string d_data;
};

class my_packet_listener_t : public packet_listener_t
{
	void accept(packet_t *packet)
	{
		//std::cout << *packet << "\n";
		packet->release(); // done with packet
	}

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		stream_t *user = reinterpret_cast<stream_t *>(stream->userdata());
		if (!user)
		{
			user = new stream_t(stream);
			stream->set_userdata(user);
		}
		assert(user);
		user->accept_tcp(packet, packetloss);
		if (!packet)
			delete user;
	}

	void accept_udp(packet_t *packet, udp_stream_t *stream)
	{
		//std::cout << "UDP: " << *packet << "\n";
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

