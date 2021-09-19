/**
 * @file main.c
 * @author alireza arzehgar (alirezaarzehgar82@gmail.com)
 * @brief endpoint for tests
 * @version 0.1
 * @date 2021-09-19
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "main.h"

int
main (int argc, char const *argv[])
{


  CU_pSuite pSuit = NULL;

  if (CU_initialize_registry() != CUE_SUCCESS)
    return CU_get_error();

  /* add functions to test */
  pSuit = CU_add_suite ("all functions", init_suite_pkt, cleanup_suite_pkt);

  if (pSuit == NULL)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }

  /* add tests */
  for (size_t i = 0; i < sizeof (functions) / sizeof (function_t); i++)
    {
      if (CU_add_test (pSuit, functions[i].description, functions[i].func) == NULL)
        return CU_get_error();
    }

  /* run test */
  CU_basic_set_mode (CU_BRM_VERBOSE);

  CU_basic_run_tests();

  CU_cleanup_registry();

  return CU_get_error();
}
