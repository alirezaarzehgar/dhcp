#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include "cli/tests.h"
#include "lease/tests.h"

#include "pkt_test.h"
#include "cli_tests.h"
#include "network_tests.h"
#include "lease_tests.h"

#if !defined(TESTS_MAIN_H)
#define TESTS_MAIN_H

CU_SuiteInfo suites[] =
{
  {
    .pName = "pkt suite",
    .pInitFunc = initSuitePkt,
    .pCleanupFunc = cleanupSuitePkt,
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
    .pTests = cli_tests,
  },
  CU_SUITE_INFO_NULL,
};

#endif
