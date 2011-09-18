#include "shared/misc.h"
#include "packet.h"
#include "packet_listener.h"
#include "pcap_reader.h"
#include "pcap_writer.h"
#include "tcp_reassembler.h"
#include <string>
#include <string.h>
#include <iostream>
#include </usr/include/openssl/sha.h>
#include <boost/foreach.hpp>

class packet_listener_t;

std::string to_hex(const uint8_t *buf, int size)
{
	std::string r;
	while (size)
	{
		char locbuf[3];
		sprintf(locbuf, "%02x", *buf);
		r = r + locbuf;
		--size; ++buf;
	}
	return r;
}

struct stream_t
{
	stream_t(tcp_stream_t *stream) :
		d_stream(stream),
		d_key(to_str(*stream))
	{
		SHA1_Init(&d_shactx);
	}

	~stream_t()
	{
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
				SHA1_Update(&d_shactx, toplayer->begin(), toplayer->size());
			}
			packet->release();
		}
		else
		{
			//std::cout << "TCP " << d_key << " finally closed, got " << d_data.size() << " bytes data\n";
			uint8_t buf[SHA_DIGEST_LENGTH];
			SHA1_Final(buf, &d_shactx);
			printf("%s %s\n", to_hex(buf, SHA_DIGEST_LENGTH).c_str(), d_key.c_str());
		}
	}

	tcp_stream_t *d_stream; // note, not valid after accept_tcp(NULL, ..) has been called
	SHA_CTX d_shactx;
	std::string d_key;
};

class my_packet_listener_t : public packet_listener_t
{
public:
	pcap_writer_t *d_writer;
	my_packet_listener_t() : d_writer(NULL) {}
	~my_packet_listener_t() { delete d_writer; d_writer = NULL; }

	void begin_capture(const std::string &name, int linktype, int snaplen)
	{
		std::string bname = basename(name.c_str());
		std::string fname = "writer_" + bname;
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
			(*d_writer) << packet;
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
		packet->release(); // done with packet
	}

	void accept_error(packet_t *packet, const char *error)
	{
		std::cout << "ERROR: " << *packet << ": " << error << "\n";
		exit(-1);
		packet->release(); // done with packet
	}
};

void printhelp(const char *argv0)
{
	printf("%s [--live <device>] [--bpf <bpf>] [pcaps]\n", basename(argv0));
}

int main(int argc, char *argv[])
	try
{
	std::vector<std::string> positional;
	bool live = false;
	std::string filter;
	for (int n=1; n<argc; ++n)
	{
		std::string arg = argv[n];
		bool havenext = n+1 < argc;
		if (havenext && (arg == "--bpf" || arg == "--filter"))
		{ filter = argv[n+1]; ++n; }
		else if (arg == "--live")
			live = true;
		else if (arg == "-h" or arg == "--help")
		{
			printhelp(argv[0]);
			return -1;
		}
		else positional.push_back(arg);
	}
	if (live && positional.size()>1)
		throw format_exception("can only do live capture on one device (use 'any' for all)");
	if (!live && positional.empty())
		throw format_exception("need at least one pcap file");

	my_packet_listener_t listener;
	pcap_reader_t reader(&listener);
	if (!live)
		BOOST_FOREACH(const std::string &file, positional)
			reader.read_file(file, filter);
	else
	{
		std::string device = "any";
		if (!positional.empty())
			device = positional[0];
		reader.open_live_capture(device, true, filter);
		while (1)
			reader.read_packets();
	}
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

