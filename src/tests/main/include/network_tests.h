#include <CUnit/TestDB.h>

#include "network/tests.h"

#if !defined(NETWORK_TEST_ARRAY_H)
#define NETWORK_TEST_ARRAY_H

CU_TestInfo network_tests[] =
{
  {"network module test", test_network},
  CU_TEST_INFO_NULL,
};

#endif