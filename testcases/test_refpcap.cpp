#include <boost/test/unit_test.hpp>
#include "pcap_reader.h"
#include "tcp_reassembler.h"
#include <boost/uuid/sha1.hpp>
#include <map>

using boost::uuids::detail::sha1;

std::string to_str(sha1 &hash)
{
	unsigned int dig[5];
	hash.get_digest(dig);
	char buf[256];
	sprintf(buf, "%08x %08x %08x %08x %08x", dig[0], dig[1], dig[2], dig[3], dig[4]);
	return buf;
}

typedef std::map<std::string, std::string> resultmap_t;

// this listener places sha1 hashes of all streams in d_out
struct hashing_listener_t : public packet_listener_t
{
	resultmap_t d_out;

	void finish(tcp_stream_t *stream)
	{
		sha1 *sha = reinterpret_cast<sha1 *>(stream->userdata());
		std::string key = to_str(*stream);
		if (d_out.count(key) == 0)
			d_out[key] = to_str(*sha);
	}

	virtual void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		sha1 *sha = reinterpret_cast<sha1 *>(stream->userdata());
		if (packet)
		{
			if (!sha) { sha = new sha1; stream->set_userdata(sha); }

			layer_t *toplayer = packet->layer(-1);
			if (toplayer && toplayer->type() == layer_data)
				sha->process_bytes(toplayer->data(), toplayer->size());

			if (stream->closed())
				finish(stream);

			packet->release();
		}
		else
		{
			finish(stream);
			stream->set_userdata(NULL);
			delete sha;
		}
	}
};

std::ostream &operator <<(std::ostream &os, const hashing_listener_t &l)
{
	for (std::map<std::string, std::string>::const_iterator i = l.d_out.begin(); i!=l.d_out.end(); ++i)
		os << '(' << i->first << ", " << i->second << ')' << "\n";
	return os;
}

bool compare(const resultmap_t &test, const resultmap_t &ref)
{
	bool result = true;
	for (resultmap_t::const_iterator i = ref.begin(); i!= ref.end(); ++i)
	{
		if (!test.count(i->first))
		{
			result = false;
			BOOST_ERROR(i->first + " not found in test");
		}
		if (i->second != test.find(i->first)->second)
		{
			result = false;
			BOOST_ERROR(i->first + " differs, got " + test.find(i->first)->second + " needed " + i->second);
		}
	}
	for (resultmap_t::const_iterator i = test.begin(); i!= test.end(); ++i)
	{
		if (!ref.count(i->first))
		{
			result = false;
			BOOST_ERROR(i->first + " not found in reference");
		}
	}
	return result;
}

BOOST_AUTO_TEST_CASE(bla)
{
	resultmap_t reference;
	reference["192.168.9.2:2001 -> 192.168.9.3:60254"] = "2a80023e 426fc810 72f224a2 d4b6e9d3 d8de8452";
	reference["192.168.9.2:2002 -> 192.168.9.3:47263"] = "f0c4c232 5f199101 a8aec09d 48cb5abd b6cffefb";
	reference["192.168.9.2:2003 -> 192.168.9.3:48273"] = "03381cd2 f3bd3be3 98bf93e5 11621e6c e0e8012f";
	reference["192.168.9.3:47263 -> 192.168.9.2:2002"] = "7cc5a783 0f675484 376947e4 f4c4dbcf 7147e317";
	reference["192.168.9.3:48273 -> 192.168.9.2:2003"] = "bd256242 4d82233f 45c13534 8e811dce a7598396";
	reference["192.168.9.3:60254 -> 192.168.9.2:2001"] = "18456bb3 24b3b6ab 5674c21d a0b98b5e 32340a8d";

	hashing_listener_t listener;
	pcap_reader_t reader(&listener);
	reader.read_file("ref.pcap");

	BOOST_CHECK(compare(listener.d_out, reference));
}

