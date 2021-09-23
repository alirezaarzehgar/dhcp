#include <CUnit/TestDB.h>

#include "lease/tests.h"

#if !defined(LEASE_TEST_ARRAY_H)
#define LEASE_TEST_ARRAY_H

CU_TestInfo lease_tests[] =
{
  {"lease module test", test_lease},
  CU_TEST_INFO_NULL,
};

#endif // LEASE_TEST_ARRAY_H
