// a simple wrapper around basename(2) with a const argument which isn't
// provided on POSIX systems.
// Note that the returned argument should be free()d.

const char* basename_r(const char* path);
