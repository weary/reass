#include "reass/packet.h"
#include "reass/packet_listener.h"
#include "reass/pcap_reader.h"
#include "reass/pcap_writer.h"
#include "reass/tcp_reassembler.h"
#include <string>
#include <string.h>
#include <iostream>
#include <stdarg.h>
#include <boost/foreach.hpp>
#include <boost/filesystem/convenience.hpp>


class packet_listener_t;

struct stream_t
{
	stream_t(tcp_stream_t *stream) :
		d_prefix(stream->initiator() ? "i" : "r")
	{
	}

	~stream_t() {}

	void accept_tcp(packet_t *packet, int packetloss)
	{
		auto_release_t<packet_t> releaser(packet);
		if (packet)
		{
			layer_t *toplayer = packet->layer(-1);
			if (!toplayer || toplayer->type() != layer_data)
				return;

			d_data.append((const char *)toplayer->begin(), toplayer->size());

			// find eol and print
			while (1)
			{
				std::string::size_type i = d_data.find('\n');
				if (i == std::string::npos)
					break;

				std::cout << d_prefix <<": " << d_data.substr(0, i) << std::endl;
				d_data = d_data.substr(i+1);
			}
		}
		else
		{
			if (!d_data.empty())
			        std::cout << d_prefix <<": " << d_data << std::endl;
		}
	}

protected:
	std::string d_prefix, d_data;
};

class my_packet_listener_t : public packet_listener_t
{
public:
	my_packet_listener_t() {}
	~my_packet_listener_t() {}

	void begin_capture(const std::string &name, int linktype, int snaplen)
	{
		fprintf(stderr, "new capture '%s'\n", name.c_str());
	}

	void new_packet(packet_t *packet, uint64_t packetnr)
	{
		++packetnr; // wireshark's packetnr's are 1-based
		packet->set_userdata((void *)packetnr);
		//debug_packet(packet, "start parsing");
	}

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		if (packet)
			debug_packet(packet, "accepted packet");
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

	void accept_error(packet_t *packet, const char *error)
	{
		packet->set_userdata(NULL); // 'new_packet' not called
		debug_packet(packet, "error: %s", error);
		throw format_exception("error parsing packet '%s': %s", to_str(*packet).c_str(), error);
	}

	void debug_packet(packet_t *packet, const char *fmt, ...)
	{
		assert(packet);

		va_list ap;
		char buf[256];

		va_start(ap, fmt);
		vsnprintf(buf, 256, fmt, ap);
		va_end(ap);

		uint64_t packetnr = (uint64_t)packet->userdata();
		struct timeval ts = packet->ts();

		fprintf(stderr, "%4ld %6d.%06d %s\n", packetnr, (unsigned)ts.tv_sec,
				(unsigned)ts.tv_usec, buf);
	}

};

void printhelp(const char *argv0)
{
	printf("\nprint all data in captured streams to stdout\n\n");
	printf("%s [--live <device>] [--bpf <bpf>] [pcaps]\n", boost::filesystem::basename(argv0).c_str());
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
	{
		BOOST_FOREACH(const std::string &file, positional)
			reader.read_file(file, filter);
	}
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

