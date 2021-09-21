#include <CUnit/TestDB.h>

#include "pkt/tests.h"

#include "pkt/validate_test.h"

#if !defined(TEST_PKT_ARRAY_H)
#define TEST_PKT_ARRAY_H

CU_TestInfo pkt_tests[] =
{
  {"validation function pkt_is_msg_type_valid_test", pkt_is_msg_type_valid_test},
  {"validation function pkt_is_msg_type_option_valid_test", pkt_is_msg_type_option_valid_test},
  {"validation function pkt_is_requested_ip_addr_option_valid_test", pkt_is_requested_ip_addr_option_valid_test},
  {"validation function pkt_is_host_name_option_valid_test", pkt_is_host_name_option_valid_test},
  {"validation function pkt_is_parameter_list_valid_test", pkt_is_parameter_list_valid_test},
  {"validation function pkt_is_valid_server_identifier_test", pkt_is_valid_server_identifier_test},
  {"get magic cookie", pkt_get_magic_cookie_test},
  {"get message type", pkt_get_dhcp_message_type_test},
  {"get requested ip address", pkt_get_requested_ip_address_test},
  {"get host name", pkt_get_host_name_test},
  {"get parameter list", pkt_get_parameter_list_test},
  {"get server identifier", pkt_get_server_identifier_test},
  CU_TEST_INFO_NULL,
};


#endif // TEST_PKT_ARRAY_H
