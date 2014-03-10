/*
 * Copyright 2011 Hylke Vellinga
 */


#include "reass/ip_address.h"
#include "reass/helpers/misc.h"
#include <arpa/inet.h>
#include <netinet/in.h>

BOOST_STATIC_ASSERT_MSG(sizeof(in6_addr) == 128/8, "ipv6 addresses must be 128 bits");

BOOST_STATIC_ASSERT_MSG(offsetof(ip_address_t, v4.sin_port) == offsetof(ip_address_t, v6.sin6_port), "structure alignment issue");

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

