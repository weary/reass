#include <boost/test/unit_test.hpp>
#include <stdint.h>
#include "free_list.h"

struct dummy_t : public free_list_member_t<dummy_t>
{
	dummy_t(dummy_t *&free_head) :
		free_list_member_t<dummy_t>(free_head)
	{}
};

BOOST_AUTO_TEST_CASE(freelist)
{
	const unsigned preclaim = 1000000;
	free_list_container_t<dummy_t> container(preclaim);
#if !defined(NO_REUSE) and defined(DEBUG)
	BOOST_CHECK_EQUAL(container.objectcount(), preclaim);
#endif
	container.claim()->release();

	// destructor of free_list_container_t used to trigger a segfault because it
	// recursively destructed. that is tested here.
}
