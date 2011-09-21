/*
 * Copyright 2011 Hylke Vellinga
 */


#include <boost/intrusive/list.hpp>
#include <boost/array.hpp>
#include "shared/misc.h"

typedef boost::intrusive::list_base_hook<
		boost::intrusive::link_mode<
			boost::intrusive::auto_unlink>
	> doublelinked_hook_t;

const uint64_t basetime = 1314514000;

// FIXME: minimal granularity is 1 sec, which is very large for 1GB/s and up
template<int MAX_TIMEOUT, int GRANULARITY, typename STREAMTYPE>
struct timeouts_t
{
	typedef boost::intrusive::list<STREAMTYPE, boost::intrusive::constant_time_size<false> > streamlist_t;

	timeouts_t() : d_now(0), d_now_in_slots(0) {}

	void set_time(uint64_t now, streamlist_t &out);
	void set_timeout(uint64_t when, STREAMTYPE *stream1, STREAMTYPE *stream2);

protected:
	enum { max_timeout = MAX_TIMEOUT };
	enum { granularity = GRANULARITY };
	enum { slots = max_timeout / granularity };
	BOOST_STATIC_ASSERT(slots * granularity == max_timeout); // MAX_TIMEOUT must be a multiple of GRANULARITY

	uint64_t d_now;
	uint64_t d_now_in_slots; // points to the slot that will timeout when the time increases one granularity
	boost::array<streamlist_t, slots> d_timeouts;
};

template<int MAX_TIMEOUT, int GRANULARITY, typename STREAMTYPE>
inline void timeouts_t<MAX_TIMEOUT, GRANULARITY,STREAMTYPE>::set_time(
		uint64_t now, streamlist_t &out)
{
	unsigned n=0;
	while (now >= d_now + granularity)
	{
		out.splice(out.end(), d_timeouts[d_now_in_slots]);

		++d_now_in_slots; if (d_now_in_slots == slots) d_now_in_slots = 0;
		d_now += granularity;
		++n;

		if (n == slots) // we've done them all. no need to go over it again
			d_now = now;
	}
}

template<int MAX_TIMEOUT, int GRANULARITY, typename STREAMTYPE>
inline void timeouts_t<MAX_TIMEOUT, GRANULARITY, STREAMTYPE>::set_timeout(
		uint64_t when, STREAMTYPE *stream1, STREAMTYPE *stream2)
{
	unsigned slot;
	if (when < d_now)
		slot = 0; // in the past, set it so it will timeout asap
	else
		slot = (when - d_now) / granularity;
	if (slot >= slots)
		throw format_exception("timeout %ld exceeds max timeout %ld+%d = %ld\n",
			 	when-basetime, d_now-basetime, max_timeout, d_now + max_timeout-basetime);
		// to use last slot here: slot = slots-1;

	slot = d_now_in_slots + slot;
	if (slot >= slots) slot -= slots;

	static_cast<doublelinked_hook_t *>(stream1)->unlink();
	d_timeouts[slot].push_back(*stream1);
	if (stream2)
	{
		static_cast<doublelinked_hook_t *>(stream2)->unlink();
		d_timeouts[slot].push_back(*stream2);
	}
}
