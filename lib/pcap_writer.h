/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_PCAP_WRITER_H__
#define __REASS_PCAP_WRITER_H__

#include <boost/noncopyable.hpp>
#include "reass/helpers/misc.h"

struct pcap_writer_t : public boost::noncopyable
{
	pcap_writer_t(const std::string &fname, int linktype, int snaplen);
	~pcap_writer_t();

	void add(const packet_t *packet);
	void add(const struct pcap_pkthdr *hdr, const u_char *data);
protected:
	pcap_dumper_t *d_dumper;
};

inline pcap_writer_t &operator <<(pcap_writer_t &writer, const packet_t *packet)
{
	assert(packet);
	writer.add(packet);
	return writer;
}

inline pcap_writer_t::pcap_writer_t(const std::string &fname, int linktype, int snaplen) :
	d_dumper(NULL)
{
	pcap_t *p = pcap_open_dead(linktype, snaplen);
	if (!p)
		throw format_exception("failed to open handle for '%s', %s", fname.c_str(), pcap_geterr(p));

	d_dumper = pcap_dump_open(p, fname.c_str());
	if (!d_dumper)
	{
		pcap_close(p);
		throw format_exception("failed to open output '%s', %s", fname.c_str(), pcap_geterr(p));
	}
	pcap_close(p);
}

inline pcap_writer_t::~pcap_writer_t()
{
	if (d_dumper)
		pcap_dump_close(d_dumper);
}

inline void pcap_writer_t::add(const packet_t *packet)
{
	assert(packet);
	pcap_dump((u_char *)d_dumper, &packet->pckthdr(), packet->data());
}

inline void pcap_writer_t::add(const struct pcap_pkthdr *hdr, const u_char *data)
{
	assert(hdr && data);
	pcap_dump((u_char *)d_dumper, hdr, data);
}

#endif // __REASS_PCAP_WRITER_H__

