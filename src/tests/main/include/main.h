#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include "pkt/tests.h"
#include "cli/tests.h"
#include "network/tests.h"
#include "lease/tests.h"

#if !defined(TESTS_MAIN_H)
#define TESTS_MAIN_H

CU_TestInfo pkt_tests[] =
{
  {"pkt module test", test_pkt},
	CU_TEST_INFO_NULL,
};

CU_TestInfo network_tests[] =
{
  {"network module test", test_network},
	CU_TEST_INFO_NULL,
};

CU_TestInfo lease_tests[] =
{
  {"lease module test", test_lease},
	CU_TEST_INFO_NULL,
};

CU_TestInfo cli_tests[] =
{
  {"cli module test", test_cli},
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo suites[] =
{
  {
    .pName = "pkt suite",
    .pInitFunc = init_suite_pkt,
    .pCleanupFunc = cleanup_suite_pkt,
    .pTests = pkt_tests
  },
  {
    .pName = "network suite",
    .pInitFunc = init_suite_network,
    .pCleanupFunc = cleanup_suite_network,
    .pTests = network_tests
  },
  {
    .pName = "lease suite",
    .pInitFunc = init_suite_lease,
    .pCleanupFunc = cleanup_suite_lease,
    .pTests = lease_tests
  },
  {
    .pName = "cli suite",
    .pInitFunc = init_suite_cli,
    .pCleanupFunc = cleanup_suite_cli,
    .pTests = cli_tests
  },
  CU_SUITE_INFO_NULL
};

#endif // TESTS_MAIN_H
