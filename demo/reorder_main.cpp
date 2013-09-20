#include "reass/pcap_reader.h"
#include "reass/pcap_writer.h"
#include <boost/foreach.hpp>
#include <boost/algorithm/string/trim.hpp>
#include "boost/scope_exit.hpp"
#include <boost/algorithm/string/join.hpp>
#include <stdexcept>
#include <sys/mman.h>

static void writeline(int handle, const std::string &line)
{
	size_t pos = 0;
	while (pos < line.size())
	{
		ssize_t c = ::write(handle, line.data() + pos, line.size() - pos);
		if (c < 0)
			unix_die("writing");
		pos = pos + c;
	}
}

struct store_packets_listener_t : public packet_listener_t
{
	store_packets_listener_t(std::vector<packet_t *> &p, int &linktype, int &snaplen) :
	 	d_p(p), d_linktype(linktype), d_snaplen(snaplen)
 	{}
	~store_packets_listener_t() {}

	void begin_capture(const std::string &name, int linktype, int snaplen)
	{
		d_linktype = linktype;
		d_snaplen = snaplen;
	}

	void accept(packet_t *packet)
	{
		d_p.push_back(packet);
	}

	void accept_error(packet_t *packet, const char *error)
	{
		d_p.push_back(packet);
	}

protected:
	std::vector<packet_t *> &d_p;
	int &d_linktype;
	int &d_snaplen;
};

std::vector<packet_t *> read_packets(const std::vector<std::string> &pcaps, int &linktype, int &snaplen)
{
	std::vector<packet_t *> out;
	store_packets_listener_t listener(out, linktype, snaplen);
	pcap_reader_t reader(&listener);
	reader.enable_tcp_reassembly(false);
	reader.enable_udp_reassembly(false);
	BOOST_FOREACH(const std::string &file, pcaps)
		reader.read_file(file);
	return out;
}

void write_packetlines(int handle, const std::vector<packet_t *> packets)
{
	BOOST_FOREACH(const packet_t *p, packets)
	{
		writeline(handle, to_str(*p) + "\n");
	}
}

std::vector<uint64_t> parse_packetnrs(int handle)
{
	using boost::algorithm::trim;
	using boost::algorithm::trim_copy;

	std::vector<uint64_t> out;

	uint64_t fsize = filesize(handle);
	char *map = reinterpret_cast<char *>(mmap(NULL, fsize, PROT_READ, MAP_SHARED, handle, 0));
	if (!map) unix_die("mmap");

	BOOST_SCOPE_EXIT((&map)(fsize))
	{
		if (map) { munmap(reinterpret_cast<void *>(map), fsize); map = NULL; }
	} BOOST_SCOPE_EXIT_END;

	uint64_t line = 0;
	char *cur = map;
	while (cur)
	{
		++line;
		char *next = reinterpret_cast<char *>(memchr(cur, '\n', map + fsize - cur));
		std::string s;
		if (next)
		{
			s.assign(cur, next);
			cur = next + 1;
		}
		else
		{
			s.assign(cur, map + fsize - cur);
			cur = NULL;
		}

		trim(s);
		if (s.empty() || s[0] == '#')
			continue;
		if (s[0] != '[')
			throw format_exception("could not parse line %ld, no [ at start of line", line);
		s = trim_copy(s.substr(1));
		if (s[0] < '0' || s[0] > '9')
			throw format_exception("could not parse line %ld, missing packet number", line);
		uint64_t pnr = 0;
		for (size_t n=0; n<s.size() && s[n]>='0' && s[n]<='9'; ++n)
			pnr = pnr * 10 + (s[n] - '0');
		out.push_back(pnr);
	}

	return out;
}

void write_pcap(
		const std::string &outfile,
		int linktype,
		int snaplen,
	 	const std::vector<packet_t *> &packets,
	 	const std::vector<uint64_t> &pnrs)
{
	size_t n=0;
	{
		pcap_writer_t writer(outfile, linktype, snaplen);
		BOOST_FOREACH(uint64_t p, pnrs)
		{
			// note, numbers in pnrs are 1-based
			if (p > packets.size())
				throw format_exception("invalid packetnr %ld found", p);
			writer.add(packets[p-1]);
			++n;
		}
	}
	printf("wrote %ld packets to '%s'\n", n, outfile.c_str());
}

void printhelp(const char *argv0)
{
	const char *app = basename(argv0);

	printf("Usage:\n");
	printf("  %s --interactive -o <output pcap> <input pcaps>\n", app);
	printf("\n  or\n\n");
	printf("  %s --generate <genfile.txt> <input pcaps>\n", app);
	printf("  (edit genfile.txt to your liking)\n");
	printf("  %s --parse <genfile.txt> -o <output pcap> <input pcaps>\n", app);
}

int main(int argc, char *argv[])
	try
{
	std::vector<std::string> positional;
	std::string orderfile, outfile;
	enum { mode_interactive, mode_generate, mode_parse, mode_unknown } mode = mode_unknown;
	for (int n=1; n<argc; ++n)
	{
		std::string arg = argv[n];
		bool havenext = n+1 < argc;
		if (arg == "--interactive" || arg == "-i")
		{
			if (mode != mode_unknown)
				throw std::runtime_error("can only use one of -i, -g and -p");
			mode = mode_interactive;
		}
		else if (havenext && (arg == "--generate" || arg == "-g"))
		{
			if (mode != mode_unknown)
				throw std::runtime_error("can only use one of -i, -g and -p");
			orderfile = argv[n+1]; ++n;
			mode = mode_generate;
		}
		else if (havenext && (arg == "--parse" || arg == "-p"))
		{
			if (mode != mode_unknown)
				throw std::runtime_error("can only use one of -i, -g and -p");
			orderfile = argv[n+1]; ++n;
			mode = mode_parse;
		}
		else if (havenext && (arg == "--output" || arg == "-o"))
		{
			outfile = argv[n+1]; ++n;
		}
		else if (arg == "--help" || arg == "-h")
		{
			printhelp(argv[0]);
			return -1;
		}
		else positional.push_back(arg);
	}
	if (positional.empty())
		throw format_exception("need at least one pcap file");
	if (mode == mode_unknown)
		throw std::runtime_error("specify one of -i, -g or -p");
	if (mode == mode_generate && !outfile.empty())
		throw std::runtime_error("-o option is invalid in generate mode");
	if (mode != mode_generate && outfile.empty())
		throw std::runtime_error("specify -o for output pcap");
	if (mode == mode_interactive && !getenv("EDITOR"))
		throw std::runtime_error("$EDITOR is not set in environment");


	int linktype, snaplen;
	std::vector<packet_t *> packets = read_packets(positional, linktype, snaplen);

	int handle = -1;
	if (mode == mode_interactive || mode == mode_generate)
	{
		if (mode == mode_interactive)
		{
			char name[256];
			::strcpy(name, "genfileXXXXXX");
			handle = ::mkstemp(name);
			if (handle < 0)
				unix_die("opening tempfile");
			::unlink(name);
			orderfile = "/proc/" + to_str(getpid()) + "/fd/" + to_str(handle);
		}
		else
		{
			handle = ::creat(orderfile.c_str(), 0664);
			if (handle < 0)
				unix_die("opening file '" + orderfile + "'");
		}

		writeline(handle, "# rearrange/copy/delete lines as needed\n");
		std::string cmdline;
		if (mode == mode_interactive)
			writeline(handle, "# new pcap will be generated after you save-and-exit this editor\n");
		else
		{
			cmdline = std::string(basename(argv[0])) + " " + boost::algorithm::join(positional, " ") + " -p " + orderfile + " -o <output>.pcap";
			writeline(handle, "# to generate a re-ordered pcap: " + cmdline + "\n");
		}
		write_packetlines(handle, packets);

		if (mode == mode_generate)
			printf("\n'%s' written, now adjust it with your favourite editor. when done, use this to generate your pcap:\n\n%s\n\n", orderfile.c_str(), cmdline.c_str());
	}

	if (mode == mode_interactive)
	{ // launch editor
		int r = system((std::string(getenv("EDITOR")) + " " + orderfile).c_str());
		if (r == -1)
			unix_die("fork'ing to launch editor");
	}

	if (mode == mode_interactive || mode == mode_parse)
	{
		if (mode == mode_interactive)
		{
			::lseek(handle, 0, SEEK_SET);
		}
		else
		{
			handle = open(orderfile.c_str(), O_RDONLY);
			if (handle < 0)
				unix_die("opening tempfile");
		}
		std::vector<uint64_t> pnrs = parse_packetnrs(handle);
		write_pcap(outfile, linktype, snaplen, packets, pnrs);
		printf("\nall done\n\n");
	}

	::close(handle);
	BOOST_FOREACH(packet_t *p, packets)
		p->release();
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

