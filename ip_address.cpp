/*
 * Copyright 2011 Hylke Vellinga
 */


#include "ip_address.h"
#include <arpa/inet.h>

std::ostream &operator <<(std::ostream &os, const ip_address_t &ip)
{
	char buf[INET6_ADDRSTRLEN];
	int family = ip.v4.sin_family;
	const void *addr =
		 	(family == AF_INET ? (const void *)&ip.v4.sin_addr : &ip.v6.sin6_addr);
	const char * r = inet_ntop(
			family,
		 	addr,
			buf, INET6_ADDRSTRLEN);

	if (!r) r = "unprintable";
	if (family == AF_INET)
		os << r << ':' << ntohs(ip.v4.sin_port);
	else
		os << '[' << r << "]:" << ntohs(ip.v6.sin6_port);
	return os;
}
