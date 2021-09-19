#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CUnit/Basic.h>

#include "pkt/tests.h"
#include "cli/tests.h"
#include "network/tests.h"
#include "lease/tests.h"

#if !defined(TESTS_MAIN_H)
#define TESTS_MAIN_H

typedef void (*test_func_t)();

struct function
{
  test_func_t func;
  const char *description;
};

typedef struct function function_t;

function_t functions[] =
{
	/* examples */
  {test_pkt, "pkt module test"},
  {test_cli, "cli module test"},
  {test_lease, "lease module test"},
  {test_network, "network module test"}

	/* pkt functions */

	/* cli functions */

	/* lease functions */

	/* network fucntions */
};

#endif // TESTS_MAIN_H
