#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include "pkt_test.h"

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
  CU_SUITE_INFO_NULL,
};

#endif
