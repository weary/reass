#ifndef __REASS_FIND_H__
#define __REASS_FIND_H__

#include "reass/packet.h"
#include "reass/packet_listener.h"
#include "reass/pcap_reader.h"
#include "reass/pcap_writer.h"
#include "reass/tcp_reassembler.h"
#include "reass/helpers/timeval_helpers.h"
#include <boost/regex.hpp>

// wraps one side of a tcp-stream
class regex_stream_t
{
public:
	regex_stream_t(const boost::regex &regex);
	~regex_stream_t();

	// does matching
	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream);

protected:
	void print(const timeval &tv, const std::string &s);

	const boost::regex &d_regex;
	bool d_matched;

	std::string d_data;
	struct timeval d_match_timestamp;

	std::vector<uint64_t> d_packets; // only filled if g_write_pcap
};


class regex_matcher_t : public packet_listener_t
{
public:
	regex_matcher_t(const std::string &regex);

	void set_pcap_reader(const pcap_reader_t *reader) { d_reader = reader; }
	void flush() { d_reassembler.flush(); }

protected:
	void accept(packet_t *packet);
	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream);
	void accept_error(packet_t *packet, const char *error);

	boost::regex d_regex;
	const pcap_reader_t *d_reader;

	tcp_reassembler_t d_reassembler;
};

class stream_writer_t : public packet_listener_t
{
public:
	stream_writer_t(const std::string &outname, const std::string &bpf);
	~stream_writer_t();

	void write_pcap();

protected:
	void begin_capture(const std::string &name, int linktype, int snaplen);
	void accept(packet_t *packet);

	pcap_reader_t d_reader;
	std::string d_bpf;
	pcap_writer_t *d_writer;
	const std::string d_fname;
	uint64_t d_first_packetnr_in_next_file;

	std::vector<uint64_t>::const_iterator d_match_iter;

	int d_linktype;
	int d_snaplen;
};

#endif // __REASS_FIND_H__
