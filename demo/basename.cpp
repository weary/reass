#include "basename.h"
#include <strings.h>
#include <stdlib.h>
#include <libgen.h>

const char* basename_r(const char* path)
{
	char *path_copy = strdup(path);
	const char *rv = strdup(basename(path_copy));
	free(path_copy);
	return rv;
}
