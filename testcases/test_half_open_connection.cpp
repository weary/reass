#include <boost/test/unit_test.hpp>
#include "pcap_reader.h"
#include "tcp_reassembler.h"
#include <vector>


// ===============================TEST TOOLING=====================================
// test_pcap_reader_t and test_listener_t allow comparing the order of the pcap
// to the order in which the packets were delivered to the accept_tcp function,
// as well as whether or not the streams were partnered at the time the packets
// were processed.


size_t hash_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
	return std::hash<std::string>{}(std::string(reinterpret_cast<const char *>(data), hdr->caplen));
}


size_t hash_reass_packet(const packet_t *packet)
{
	return hash_packet(&packet->pckthdr(), packet->data());
}


struct test_pcap_reader_t : public packet_entrypoint_t
{
	test_pcap_reader_t(packet_listener_t *listener = NULL, bool enable_tcp = true, bool enable_udp = true);
	~test_pcap_reader_t();

	void read_file(const std::string &fname);
	void handle_packet(const struct pcap_pkthdr *hdr, const u_char *data);
	std::vector<size_t> packet_hashes;  // When done reading the file, this contains the hash of each packet in order
protected:
	pcap_t *d_pcap;
};


test_pcap_reader_t::test_pcap_reader_t(packet_listener_t *listener, bool enable_tcp, bool enable_udp) :
	packet_entrypoint_t(listener, enable_tcp, enable_udp), d_pcap(NULL)
{
}


test_pcap_reader_t::~test_pcap_reader_t()
{
	if (d_pcap)
		pcap_close(d_pcap);
}


void test_pcap_reader_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	reinterpret_cast<test_pcap_reader_t *>(user)->handle_packet(hdr, data);
}


void test_pcap_reader_t::handle_packet(const struct pcap_pkthdr *hdr, const u_char *data)
{
	packet_hashes.push_back(hash_packet(hdr, data));
	packet_entrypoint_t::handle_packet(hdr, data);
}


void test_pcap_reader_t::read_file(const std::string &fname)
{
	if (d_pcap)
		throw format_exception("Test pcap_reader can only read one file");

	char errbuf[PCAP_ERRBUF_SIZE];
	d_pcap = pcap_open_offline(fname.c_str(), errbuf);
	if (!d_pcap)
		throw format_exception("Could not open pcap '%s', %s", fname.c_str(), errbuf);

	set_linktype(pcap_datalink(d_pcap));

	d_listener->begin_capture(fname, linktype(), pcap_snapshot(d_pcap));

	const int r = pcap_dispatch(d_pcap, -1, &test_pcap_reader_callback, (u_char *)this);
	if (r == -1)
		throw format_exception("Pcap reader failed, %s", pcap_geterr(d_pcap));
}


struct test_listener_t : packet_listener_t
{
	std::vector<std::pair<bool, size_t>> packet_states;  // Each entry contains have_partner and a hash of the data

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream) override;
};


void test_listener_t::accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
{
	if (packet)
		packet_states.push_back({
			stream->have_partner(),
			hash_reass_packet(packet)
		});
}
// ===========================END OF TEST TOOLING==================================


BOOST_AUTO_TEST_CASE(stream_partnering_after_desync_rst_test)
{
	test_listener_t listener;
	test_pcap_reader_t reader(&listener);
	reader.read_file("rst_after_bad_server_timeout.pcap");

	// First we check that all packets from the pcap have been delivered in the accept_tcp function:
	BOOST_CHECK_EQUAL(listener.packet_states.size(), reader.packet_hashes.size());

	// There should be no more packets stuck in a delayed state, so a forced flush shouldn't change anything:
	const size_t accepted_frames = listener.packet_states.size();
	reader.flush();
	BOOST_CHECK_MESSAGE(listener.packet_states.size() == accepted_frames,
		"Flushing caused TCP reassembly to accept extra frames");

	BOOST_REQUIRE_MESSAGE(listener.packet_states.size() == 35,  // REQUIREd because we check entries up to #35 below
		"Unexpected number of accepted frames! Got " << listener.packet_states.size() << " but expected 35.");

	// Packets 1 to 15 and 19 to 35 should be delivered in-order, with partnered streams.
	// Note; the minus-ones appear because Wireshark uses one-based indexing for pcap frames.
	for (unsigned int i = 1; i <= 15; ++i)
	{
		BOOST_CHECK_MESSAGE(listener.packet_states[i - 1].second == reader.packet_hashes[i - 1],
			"Accepted frame " << i << " didn't match frame " << i << " in pcap file");
		BOOST_CHECK_MESSAGE(listener.packet_states[i - 1].first == true,
			"Streams weren't partnered when accepting packet " << i);
	}
	for (unsigned int i = 19; i <= 35; ++i)
	{
		BOOST_CHECK_MESSAGE(listener.packet_states[i - 1].second == reader.packet_hashes[i - 1],
			"Accepted frame " << i << " didn't match frame " << i << " in pcap file");
		BOOST_CHECK_MESSAGE(listener.packet_states[i - 1].first == true,
			"Streams weren't partnered when accepting packet " << i);
	}
}

