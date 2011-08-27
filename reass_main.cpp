#include "pcap.h"
#include <string>
#include <string.h>
//#include <vector>
#include <iostream>
#include "shared/misc.h"
#include "packet.h"


struct pcap_reader_t
{
	pcap_reader_t(const std::string &fname) : d_pcap(NULL)
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		d_pcap = pcap_open_offline(fname.c_str(), errbuf);
		if (!d_pcap)
			throw format_exception("Could not open pcap '%s', %s", fname.c_str(), errbuf);

		d_linktype = pcap_datalink(d_pcap);
	}

	void handle_packet(const struct pcap_pkthdr *hdr, const u_char *data)
	{
		packet_t *packet = new packet_t();
		packet->set(d_linktype, hdr, data);
		std::cout << *packet << std::endl;
		delete packet;
	}

	void read_packets() // read one bufferful of packets
	{
		assert(d_pcap);

		// note: don't try this at home, kids
		pcap_handler handler = reinterpret_cast<pcap_handler>(&pcap_reader_t::handle_packet);
		int r = pcap_dispatch(d_pcap, -1, handler, (u_char *)this);
		if (r == -1)
			throw format_exception("Pcap reader failed, %s", pcap_geterr(d_pcap));
		printf("got %d packets in read_packets\n", r);
	}

protected:
	pcap_t *d_pcap;
	int d_linktype;
};


int main(int arcg, char *argv[])
	try
{
	pcap_reader_t reader("/home/weary/Desktop/testdata.pcap");
	reader.read_packets();


}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

