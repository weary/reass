/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_CONFIGCHECK_H__
#define __REASS_CONFIGCHECK_H__

#ifndef NO_REASS_VERSIONCHECK
// this block of preprocessor magic is to detect if someone changed config.h
// after building the library (or tries to mix debug/release)
// If anyone knows of a better way of doing this, please tell me :)

#include "config.h"
#include <boost/preprocessor/stringize.hpp>

#ifdef DEBUG
#  define REASSVERSIONSTRING1 "d"
#else
#  define REASSVERSIONSTRING1 "u"
#endif
#ifdef NO_MEMBER_CALLBACK
#  define REASSVERSIONSTRING2 REASSVERSIONSTRING1 "d"
#else
#  define REASSVERSIONSTRING2 REASSVERSIONSTRING1 "u"
#endif
#ifdef NO_REUSE
#  define REASSVERSIONSTRING3 REASSVERSIONSTRING2 "d"
#else
#  define REASSVERSIONSTRING3 REASSVERSIONSTRING2 "u"
#endif
#ifdef UNKNOWN_LAYER_AS_ERROR
#  define REASSVERSIONSTRING4 REASSVERSIONSTRING3 "d"
#else
#  define REASSVERSIONSTRING4 REASSVERSIONSTRING3 "u"
#endif
#ifdef PRINT_STATS
#  define REASSVERSIONSTRING5 REASSVERSIONSTRING4 "d"
#else
#  define REASSVERSIONSTRING5 REASSVERSIONSTRING4 "u"
#endif
#define REASSVERSIONSTRING REASSVERSIONSTRING5 BOOST_PP_STRINGIZE(MAX_LAYERS) BOOST_PP_STRINGIZE(MAX_DELAYED_PACKETS)
#include <stdio.h>
namespace reass_test_config
{
	struct test_config_t
	{
		test_config_t(const char linkflags[]);
	};
	namespace
	{
		test_config_t test_config(REASSVERSIONSTRING);
	}
}

#endif // NO_REASS_VERSIONCHECK
#endif // __REASS_CONFIGCHECK_H__
