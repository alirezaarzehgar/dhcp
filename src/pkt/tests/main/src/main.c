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
  if (CU_initialize_registry() != CUE_SUCCESS)
    {
      fprintf (stderr, "%s\n", CU_get_error_msg());
      return CU_get_error();
    }

  if (CU_register_suites (suites) != CUE_SUCCESS)
    {
      fprintf (stderr, "%s\n", CU_get_error_msg());
      return CU_get_error();
    }

  CU_basic_set_mode (CU_BRM_VERBOSE);

  if (CU_basic_run_tests() != CUE_SUCCESS)
    {
      fprintf (stderr, "%s\n", CU_get_error_msg());
      return CU_get_error();
    }

  CU_cleanup_registry();

  return CU_get_error();
}
