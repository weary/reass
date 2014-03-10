/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_IP_ADDRESS_H__
#define __REASS_IP_ADDRESS_H__

#include <netinet/in.h>
#include <fstream>
#include <boost/functional/hash/hash.hpp>

struct ip_address_t
{
	union
	{
		sockaddr_in v4;
		sockaddr_in6 v6;
	};

	std::string ip() const;
	uint16_t port() const { return ntohs(v4.sin_port); }
};

std::ostream &operator <<(std::ostream &, const ip_address_t &);
bool operator ==(const ip_address_t &l, const ip_address_t &r);
std::size_t hash_value(const ip_address_t &s);


namespace
{
inline
bool operator ==(const in6_addr &l, const in6_addr &r)
{
#ifdef __SIZEOF_INT128__
	return  // use gcc's builtin 128-bit type for compare
		*reinterpret_cast<const __uint128_t *>(&l)
		==
		*reinterpret_cast<const __uint128_t *>(&r);
#else
	const uint64_t *lu = reinterpret_cast<const uint64_t *>(&l);
	const uint64_t *ru = reinterpret_cast<const uint64_t *>(&r);
	return lu[0] == ru[0] && lu[1] == ru[1];
#endif
}
} // nameless namespace


// compares ip and port
inline
bool operator ==(const ip_address_t &l, const ip_address_t &r)
{
	if (l.v4.sin_family != r.v4.sin_family || l.v4.sin_port != r.v4.sin_port)
		return false;

	if (l.v4.sin_family == AF_INET)
		return l.v4.sin_addr.s_addr == r.v4.sin_addr.s_addr;
	else
		return l.v6.sin6_addr == r.v6.sin6_addr;
}

inline
std::size_t hash_value(const ip_address_t &s)
{
	std::size_t r = s.v4.sin_family;
	boost::hash_combine(r, s.v4.sin_port);
	if (s.v4.sin_family == AF_INET)
		boost::hash_combine(r, s.v4.sin_addr.s_addr);
	else
		for (int n=0; n<4; ++n)
			boost::hash_combine(r, s.v6.sin6_addr.__in6_u.__u6_addr32[n]);

	return r;
}


#endif // __REASS_IP_ADDRESS_H__
