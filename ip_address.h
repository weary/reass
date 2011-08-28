/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_IP_ADDRESS_H__
#define __REASS_IP_ADDRESS_H__

#include <netinet/in.h>
#include <fstream>

struct ip_address_t
{
	union
	{
		sockaddr_in v4;
		sockaddr_in6 v6;
	};
};

std::ostream &operator <<(std::ostream &, const ip_address_t &);

#endif // __REASS_IP_ADDRESS_H__
