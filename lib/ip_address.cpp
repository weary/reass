/*
 * Copyright 2011 Hylke Vellinga
 */


#include "ip_address.h"
#include <arpa/inet.h>
#include <boost/functional/hash/hash.hpp>
#include "netinet/in.h"

static_assert(sizeof(in6_addr) == 128/8, "ipv6 addresses must be 128 bits");

static inline
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

static_assert(offsetof(ip_address_t, v4.sin_port) == offsetof(ip_address_t, v6.sin6_port), "structure alignment issue");

std::string ip_address_t::ip() const
{
	char buf[INET6_ADDRSTRLEN];
	int family = v4.sin_family;
	const void *addr =
		(family == AF_INET ? (const void *)&v4.sin_addr : &v6.sin6_addr);
	const char * r = inet_ntop(
			family,
			addr,
			buf, INET6_ADDRSTRLEN);
	if (!r) return "unprintable";

	return buf;
}


std::ostream &operator <<(std::ostream &os, const ip_address_t &ip)
{
	std::string addr = ip.ip();

	if (ip.v4.sin_family == AF_INET)
		os << addr << ':' << ip.port();
	else
		os << '[' << addr << "]:" << ip.port();
	return os;
}

// compares ip and port
bool operator ==(const ip_address_t &l, const ip_address_t &r)
{
	if (l.v4.sin_family != r.v4.sin_family)
		return false;
	if (l.v4.sin_port != r.v4.sin_port)
		return false;

	if (l.v4.sin_family == AF_INET)
		return l.v4.sin_addr.s_addr == r.v4.sin_addr.s_addr;
	else
		return l.v6.sin6_addr == r.v6.sin6_addr;
}

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

