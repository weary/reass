#include "reass_find.h"

// commandline settings
bool g_verbose = false;
bool g_write_pcap = false;
bool g_trailing_newline = true;
bool g_expand_packetloss = true;
enum { print_none, print_first, print_all } g_print_matches = print_all;
enum { ts_none, ts_utc, ts_rel, ts_abs, ts_abs_with_date } g_timestamp_format = ts_none;

// when writing pcaps, gather needed packetnr's here
std::vector<uint64_t> g_matched_packets;
struct timeval g_start = {0, 0};
// map from first packetnr in file to filename
typedef std::map<uint64_t, std::string> filemap_t;
filemap_t g_files;

/******************
 * regex_stream_t *
 ******************/

regex_stream_t::regex_stream_t(const boost::regex &regex) :
	d_regex(regex), d_matched(false)
{}

regex_stream_t::~regex_stream_t()
{
	if (d_matched)
	{
		g_matched_packets.insert(
				g_matched_packets.end(),
				d_packets.begin(), d_packets.end());
	}
}

void regex_stream_t::accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
{
	if (packet && g_write_pcap)
	{
		uint64_t packetnr = (uint64_t)packet->userdata();
		d_packets.push_back(packetnr);
	}
	if (d_matched && g_print_matches != print_all) return; // already done

	if (packetloss && g_expand_packetloss)
		d_data.append(packetloss, 'X');

	if (!packet)
		return;

	layer_t *toplayer = packet->layer(-1);
	if (!toplayer || toplayer->type() != layer_data || !toplayer->size())
		return;

	const char *cbegin, *cend;
	if (!d_data.empty())
	{
		d_data.append((const char *)toplayer->begin(), toplayer->size());
		cbegin = &d_data[0];
		cend = cbegin + d_data.size();
	}
	else
	{
		cbegin = (const char *)toplayer->begin();
		cend = cbegin + toplayer->size();
		d_match_timestamp = packet->ts();
	}

match_start:
	boost::match_results<const char *> what;
	bool at_least_partial = boost::regex_search(
			cbegin, cend, what, d_regex, boost::match_default | boost::match_partial);
	if (!at_least_partial)
	{
		d_data.clear();
		return;
	}
	else if (what[0].matched)
	{ // hit
		d_matched = true;
		if (stream->have_partner())
		{
			regex_stream_t *partner = reinterpret_cast<regex_stream_t *>(
					stream->partner()->userdata());
			partner->d_matched = true;
		}

		if (g_print_matches != print_none)
		{
			print_match_timestamp();

			// FIXME, need tty-detection and binary detection
			if (g_trailing_newline)
				printf("%s\n", what[0].str().c_str());
			else
				printf("%s", what[0].str().c_str());

			if (g_print_matches == print_all)
			{ // check for second hit in same packet
				cbegin = what[0].second;
				d_match_timestamp = packet->ts();
				goto match_start;
			}
		}
	}
	else
	{ // partial match
		cbegin = what[0].first;
		if (cbegin != d_data.data())
			d_data = std::string(cbegin, cend);
	}
}

void regex_stream_t::print_match_timestamp()
{
	switch(g_timestamp_format)
	{
		case(ts_none):
			break;
		case(ts_utc):
			printf("%d.%06d ", (int)d_match_timestamp.tv_sec, (int)d_match_timestamp.tv_usec);
			break;
		case(ts_rel):
			{
				timeval rel = d_match_timestamp - g_start;
				printf("%d.%06d ", (int)rel.tv_sec, (int)rel.tv_usec);
			}
			break;
		case(ts_abs):
		case(ts_abs_with_date):
			{
				const char *format = (g_timestamp_format == ts_abs ? "\%H:\%M:\%S" : "%F \%H:\%M:\%S");

				char outstr[200];
				struct tm tmp;
				localtime_r(&d_match_timestamp.tv_sec, &tmp);
				strftime(outstr, sizeof(outstr), format, &tmp);
				printf("%s.%06d ", outstr, (int)d_match_timestamp.tv_usec);
			}
			break;
	}
}


/*******************
 * regex_matcher_t *
 ******************/

regex_matcher_t::regex_matcher_t(const std::string &regex) :
	d_regex(regex), d_reader(NULL), d_reassembler(this)
{}

void regex_matcher_t::accept(packet_t *packet)
{
	auto_release_t<packet_t> releaser(packet);

	uint64_t packetnr = d_reader->packets_seen();
	packet->set_userdata(reinterpret_cast<void *>(packetnr));

	if (g_start.tv_sec == 0 && g_start.tv_usec == 0)
		g_start = packet->ts();

	d_reassembler.set_now(packet->ts().tv_sec);

	layer_t *top = packet->layer(-1);
	layer_t *second = packet->layer(-2);
	if (top->type() == layer_tcp ||
			(top->type() == layer_data && second->type() == layer_tcp))
	{
		releaser.do_not_release();
		d_reassembler.process(packet);
	}
}

void regex_matcher_t::accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
{
	auto_release_t<packet_t> releaser(packet);
	regex_stream_t *user = reinterpret_cast<regex_stream_t *>(stream->userdata());
	if (!user)
	{
		user = new regex_stream_t(d_regex);
		stream->set_userdata(user);
		if (stream->have_partner())
		{
			assert(stream->partner()->userdata() == NULL);
			stream->partner()->set_userdata(new regex_stream_t(d_regex));
		}
	}
	user->accept_tcp(packet, packetloss, stream);
	if (!packet)
		delete user;
}

void regex_matcher_t::accept_error(packet_t *packet, const char *error)
{
	if (g_verbose)
		fprintf(stderr, "error parsing packet %ld: %s\n", d_reader->packets_seen(), error);
	packet->release();
}


/*******************
 * stream_writer_t *
 ******************/

stream_writer_t::stream_writer_t(
		const std::string &outname, const std::string &bpf) :
	d_reader(this, false, false), d_bpf(bpf), d_writer(NULL),
d_fname(outname), d_match_iter(g_matched_packets.begin()),
	d_linktype(0), d_snaplen(0)
{
}

void stream_writer_t::write_pcap()
{
	while (d_match_iter != g_matched_packets.end())
	{
		uint64_t packetnr = *d_match_iter;
		filemap_t::const_iterator fi = g_files.upper_bound(packetnr);
		d_first_packetnr_in_next_file = fi->first; // stop condition
		--fi;

		if (g_verbose)
			fprintf(stderr, "re-reading file '%s' for packet-extraction\n",
					fi->second.c_str());

		d_reader.reset_packetcounter(fi->first - 1);
		d_reader.read_file(fi->second, d_bpf);
		d_reader.flush();
	}
}

stream_writer_t::~stream_writer_t()
{
	if (d_match_iter != g_matched_packets.end())
		throw std::runtime_error("not all packets found again on reading back pcap");

	delete d_writer;
	d_writer = NULL;
}

void stream_writer_t::begin_capture(const std::string &name, int linktype, int snaplen)
{
	if ((d_linktype !=0 || d_snaplen !=0) &&
			(d_linktype != linktype || d_snaplen != snaplen))
		throw std::runtime_error("snaplen/linktype changed! cannot mix these pcaps");
	d_linktype = linktype;
	d_snaplen = snaplen;
	d_writer = new pcap_writer_t(d_fname, d_linktype, d_snaplen);
}

void stream_writer_t::accept(packet_t *packet)
{
	auto_release_t<packet_t> releaser(packet);

	assert(d_match_iter != g_matched_packets.end());

	uint64_t cur = d_reader.packets_seen();
	uint64_t next_needed = *d_match_iter;
	assert(next_needed >= cur);
	if (next_needed < cur)
		throw std::runtime_error("missed a packet while reading files again");

	if (next_needed == cur)
	{
		++d_match_iter;
		d_writer->add(packet);
		if (d_match_iter == g_matched_packets.end() ||
				*d_match_iter >= d_first_packetnr_in_next_file)
			d_reader.stop_reading();
	}
}


void printhelp(const char *argv0)
{
	printf("usage: %s [-w FILENAME] [options] regex pcap [pcap ...]\n", argv0);
	printf("\n");
	printf("Apply a regex on all tcp streams in pcaps, printing hits and optionally saving matched streams to pcap.\n");
	printf("\n");
	printf("positional arguments:   input pcaps\n");
	printf("\n");
	printf("options:\n");
	printf("  -h, --help            show this help message and exit\n");
	printf("  --bpf BPF             pre-filter before matching\n");
	printf("  -w FILENAME           output pcap file\n");
	printf("  -v, --verbose         show more output, including pcap-parsing errors\n");
	printf("  -q, --quiet           show less output, don't show regex matches\n");
	printf("  -t[ttt]               show timestamp with matches (more t's for different formats)\n");
	printf("  --no-trailing-newline print regex matches without a trailing \\n\n");
	printf("\n");
}


int main(int argc, char *argv[])
	try
{
	std::vector<std::string> positional;
	std::string outname;
	std::string filter;
	bool quiet = false;
	for (int n=1; n<argc; ++n)
	{
		std::string arg = argv[n];
		bool havenext = n+1 < argc;
		if (havenext && (arg == "--bpf" || arg == "--filter"))
		{ filter = argv[n+1]; ++n; }
		else if (havenext && arg == "-w")
		{ outname = argv[n+1]; g_write_pcap = true; ++n; }
		else if (arg == "--no-trailing-newline")
			g_trailing_newline = false;
		else if (arg == "-v" || arg == "--verbose")
			g_verbose = true;
		else if (arg == "-q" || arg == "--quiet")
			quiet = true;
		else if (arg == "-t")
			g_timestamp_format = ts_utc;
		else if (arg == "-tt")
			g_timestamp_format = ts_rel;
		else if (arg == "-ttt")
			g_timestamp_format = ts_abs;
		else if (arg == "-tttt")
			g_timestamp_format = ts_abs_with_date;
		else if (arg == "-h" || arg == "--help")
		{
			printhelp(argv[0]);
			return -1;
		}
		else positional.push_back(arg);
	}
	if (positional.size() < 2)
		throw std::runtime_error("need at least a regex and one input");

	if (quiet)
		g_print_matches = print_none;

	{
		regex_matcher_t matcher(positional[0]);
		positional.erase(positional.begin());
		pcap_reader_t reader(&matcher, false, false);
		matcher.set_pcap_reader(&reader);
		for(const std::string &name: positional)
		{
			if (g_verbose)
				fprintf(stderr, "reading file '%s', have seen %ld packets so far\n",
						name.c_str(), reader.packets_seen());
			g_files[reader.packets_seen() + 1] = name;
			reader.read_file(name, filter);
			reader.flush();
		}
		if (g_verbose)
			fprintf(stderr, "read %ld packets total\n",
					reader.packets_seen());
		g_files[reader.packets_seen() + 1] = std::string();
		matcher.flush();
	}

	if (g_write_pcap)
	{
		if (g_matched_packets.empty())
			throw std::runtime_error("nothing matched, no pcap written");

		if (g_verbose)
			fprintf(stderr, "opening '%s' for writing %ld packets\n",
					outname.c_str(), g_matched_packets.size());

		std::sort(g_matched_packets.begin(), g_matched_packets.end());

		stream_writer_t(outname, filter).write_pcap();
		if (g_verbose)
			fprintf(stderr, "done writing pcap\n");
	}
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}
