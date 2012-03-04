/*
 * Copyright 2011 Hylke Vellinga
 */

#ifndef FORCE_INLINE

#if defined NDEBUG and defined __GNUC__
#  define FORCE_INLINE __attribute__((always_inline))
#else
#  define FORCE_INLINE
#endif

#endif
