#include <CUnit/TestDB.h>

#include "cli/tests.h"

#if !defined(CLI_TEST_ARRAY_H)
#define CLI_TEST_ARRAY_H

CU_TestInfo cli_tests[] =
{
  {"cli module test", test_cli},
  CU_TEST_INFO_NULL,
};

#endif // CLI_TEST_ARRAY_H

