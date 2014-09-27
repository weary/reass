#include <boost/test/unit_test.hpp>
#include <stdint.h>
#include "tcp_reassembler.h"

BOOST_AUTO_TEST_CASE(seq_nr)
{
	seq_nr_t a(0xffffffff);
	seq_nr_t b(0);
	seq_nr_t c(2);
	BOOST_CHECK_LT(a, b);
	BOOST_CHECK_LT(a, c);
	BOOST_CHECK_LT(b, c);

	BOOST_CHECK_EQUAL(distance(a, b), 1);
	BOOST_CHECK_EQUAL(distance(b, a), 1);
	BOOST_CHECK_EQUAL(distance(b, c), 2);
	BOOST_CHECK_EQUAL(distance(a, c), 3);
	BOOST_CHECK_EQUAL(distance(c, a), 3);
}
