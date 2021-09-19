#include <CUnit/TestDB.h>

#include "pkt/tests.h"

#if !defined(TEST_PKT_ARRAY_H)
#define TEST_PKT_ARRAY_H

CU_TestInfo pkt_tests[] =
{
  {"pkt module test", test_pkt},
	CU_TEST_INFO_NULL,
};


#endif // TEST_PKT_ARRAY_H
