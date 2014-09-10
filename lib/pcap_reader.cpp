/*
 * Copyright 2011 Hylke Vellinga
 */


#include "reass/pcap_reader.h"
#include "reass/packet_listener.h"
#include "reass/tcp_reassembler.h"
#include "reass/udp_reassembler.h"
#include "reass/config.h"
#include "reass/helpers/misc.h"

namespace
{
struct pcap_close_guard_t
{
	pcap_close_guard_t(pcap_t *&pcap) : d_pcap(pcap) {}
	~pcap_close_guard_t() { if (d_pcap) { pcap_close(d_pcap); d_pcap = NULL; } }
	pcap_t *&d_pcap;
};

}; // end of nameless namespace

pcap_reader_t::pcap_reader_t(packet_listener_t *listener,
		bool enable_tcp, bool enable_udp) :
	packet_entrypoint_t(listener, enable_tcp, enable_udp),
	d_pcap(NULL)
{}

pcap_reader_t::~pcap_reader_t()
{
	if (d_pcap) close_live_capture();
}

void pcap_reader_t::read_file(const std::string &fname, const std::string &bpf)
{
	if (d_pcap)
		throw format_exception("Cannot read pcap while already busy");

	pcap_close_guard_t closeguard(d_pcap);

	open_file(fname, bpf);
	read_packets();
}

void pcap_reader_t::open_file(const std::string &fname, const std::string &bpf)
{
	if (d_pcap)
		throw format_exception("Cannot open pcap while already busy");

	char errbuf[PCAP_ERRBUF_SIZE];
	d_pcap = pcap_open_offline(fname.c_str(), errbuf);
	if (!d_pcap)
		throw format_exception("Could not open pcap '%s', %s", fname.c_str(), errbuf);

	set_bpf(bpf);

	set_linktype(pcap_datalink(d_pcap));

	d_listener->begin_capture(fname, linktype(), snaplen());
}

void pcap_reader_t::close_file()
{
	if (!d_pcap)
		throw format_exception("Cannot close pcap without opened pcap");

	pcap_close(d_pcap);
	d_pcap = NULL;
}

void pcap_reader_t::open_live_capture(const std::string &device, bool promiscuous, const std::string &bpf, int snaplen, int buffersize)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	d_pcap = pcap_create(device.c_str(), errbuf);
	if (d_pcap == NULL)
		throw format_exception("Could not capture for device %s: %s", device.c_str(), errbuf);

	if (pcap_set_snaplen(d_pcap, snaplen) != 0)
		throw format_exception("Could not set snaplen %d for device %s", snaplen, device.c_str());

	if (pcap_set_buffer_size(d_pcap, buffersize) != 0)
		throw format_exception("Could not set buffersize %d for device %s", buffersize, device.c_str());

	if (pcap_set_promisc(d_pcap, promiscuous) != 0)
		throw format_exception("Could not set promisc mode for device %s", promiscuous, device.c_str());

	if (pcap_set_timeout(d_pcap, 1000) != 0)
		throw format_exception("Could not set timeout for device %s", device.c_str());

	if (pcap_activate(d_pcap) != 0)
		throw format_exception("Could not activate capture on device %s", device.c_str());

	set_bpf(bpf);

	set_linktype(pcap_datalink(d_pcap));

	d_listener->begin_capture(device, this->linktype(), this->snaplen());
}

void pcap_reader_t::set_bpf(const std::string &bpf)
{
	if (bpf.empty())
		return;

	// we don't specify the netmask, so filters for ipv4 broadcasts will fail
	if (pcap_compile(d_pcap, &d_bpf, bpf.c_str(), true, PCAP_NETMASK_UNKNOWN) < 0)
		throw format_exception("Could not compile bpf filter '%s', %s", bpf.c_str(), pcap_geterr(d_pcap));
	if (pcap_setfilter(d_pcap, &d_bpf) < 0)
		throw format_exception("Could not activate bpf filter '%s', %s", bpf.c_str(), pcap_geterr(d_pcap));
}


void pcap_reader_t::close_live_capture()
{
	pcap_close(d_pcap);
	d_pcap = NULL;
}

void pcap_reader_t::stop_reading()
{
	pcap_breakloop(d_pcap);
}

#ifdef NO_MEMBER_CALLBACK
void extra_callback_hop(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	reinterpret_cast<packet_entrypoint_t *>(user)->handle_packet(hdr, data);
}
#endif

void pcap_reader_t::read_packets() // read one bufferful of packets
{
	assert(d_pcap);

#ifndef NO_MEMBER_CALLBACK
	// note: don't try this at home, kids
	pcap_handler handler = reinterpret_cast<pcap_handler>(&packet_entrypoint_t::handle_packet);
#else
	pcap_handler handler = &extra_callback_hop;
#endif
	int r = pcap_dispatch(d_pcap, -1, handler, (u_char *)this);
	if (r == -1)
		throw format_exception("Pcap reader failed, %s", pcap_geterr(d_pcap));
}

