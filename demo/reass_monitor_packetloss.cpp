#include "reass/packet.h"
#include "reass/packet_listener.h"
#include "reass/pcap_reader.h"
#include "reass/pcap_writer.h"
#include "reass/tcp_reassembler.h"
#include <string>
#include <string.h>
#include <iostream>
#include <openssl/sha.h>
#include <boost/foreach.hpp>

class packet_listener_t;

class my_packet_listener_t : public packet_listener_t
{
public:
	my_packet_listener_t(uint32_t every) :
		d_prev_ts(0), d_every(every),
		d_single_sided(0), d_full_streams(0), d_packetloss(0)
	{}
	~my_packet_listener_t() { }

	void begin_capture(const std::string &name, int linktype, int snaplen)
	{
		printf("new capture '%s'\n", name.c_str());
	}

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		if (!stream->userdata())
		{
			stream->set_userdata((void *)1);
			if (!stream->have_partner())
			{
				++d_single_sided;
				//printf("%s is single-sided\n", to_str(*stream).c_str());
			}
			else
				++d_full_streams;
		}
		d_packetloss += packetloss;

		if (packet)
		{
			uint64_t now = packet->ts().tv_sec;
			if (d_prev_ts + d_every < now)
			{
				printf("%ld: ", now);
				print_status();
				d_prev_ts = now;
			}
			packet->release();
		}
	}

	void print_status() const
	{
		printf("%ld streams-with-partner, %ld single-streams, %ld bytes lost\n",
				d_full_streams, d_single_sided, d_packetloss);
	}

	void accept_error(packet_t *packet, const char *error)
	{
		if (strncmp(error, "unsupported protocol ", 21) != 0)
			throw format_exception("error parsing packet '%s': %s", to_str(*packet).c_str(), error);
	}

	uint64_t d_prev_ts;
	uint32_t d_every;
	uint64_t d_single_sided;
	uint64_t d_full_streams;
	uint64_t d_packetloss;
};

void printhelp(const char *argv0)
{
	printf("\n%s will monitor connections and print every x seconds a statusline telling\n", basename(argv0));
	printf("the number of new tcp connections and the number of missing bytes from those streams\n\n");
	printf("%s [--live <device>] [--bpf <bpf>] [--every <seconds>] [pcaps]\n", basename(argv0));
}

int main(int argc, char *argv[])
	try
{
	std::vector<std::string> positional;
	bool live = false;
	std::string filter;
	uint32_t every = 5*60;
	for (int n=1; n<argc; ++n)
	{
		std::string arg = argv[n];
		bool havenext = n+1 < argc;
		if (havenext && (arg == "--bpf" || arg == "--filter"))
		{ filter = argv[n+1]; ++n; }
		else if (havenext && (arg == "--every" || arg == "-e"))
		{ every = boost::lexical_cast<uint32_t>(argv[n+1]); ++n; }
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

	my_packet_listener_t listener(every);
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
	listener.print_status();
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

