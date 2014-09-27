/*
 * Copyright 2011 Hylke Vellinga
 */


#include "checkconfig.h"

#ifndef NO_REASS_VERSIONCHECK

#include <string.h>
#include <stdexcept>

namespace reass_test_config
{
	static const char libraryflags[] = REASSVERSIONSTRING;

	test_config_t::test_config_t(const char linkflags[])
	{
		if (strcmp(linkflags, libraryflags) != 0)
			throw std::runtime_error("reass built with different -DDEBUG flag or config.h contents");
	}
}

#endif // NO_REASS_VERSIONCHECK
