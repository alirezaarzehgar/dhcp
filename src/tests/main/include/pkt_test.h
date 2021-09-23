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
  {"validation function pkt_is_ip_address_lease_time_option_valid_test", pkt_is_ip_address_lease_time_option_valid_test},
  {"validation function pkt_lease_time_hex2long_test", pkt_lease_time_hex2long_test},
  {"validation function pkt_lease_time_long2hex_test", pkt_lease_time_long2hex_test},
  {"validation function pkt_is_valid_subnet_mask_test", pkt_is_valid_subnet_mask_test},
  {"validation function pkt_is_address_valid_test", pkt_is_address_valid_test},
  {"validation function pkt_is_valid_router_test", pkt_is_valid_router_test},
  {"validation function pkt_is_valid_string_test", pkt_is_valid_string_test},
  {"validation function pkt_is_domain_name_option_valid_test", pkt_is_domain_name_option_valid_test},
  {"get magic cookie", pkt_get_magic_cookie_test},
  {"get message type", pkt_get_dhcp_message_type_test},
  {"get requested ip address", pkt_get_requested_ip_address_test},
  {"get host name", pkt_get_host_name_test},
  {"get parameter list", pkt_get_parameter_list_test},
  {"get server identifier", pkt_get_server_identifier_test},
  {"convert ip string to hex", pkt_ip_str2hex_test},
  {"convert ip hex to string", pkt_ip_hex2str_test},
  {"get ip address lease time", pkt_get_ip_address_lease_time_test},
  {"offer file test", pkt_offer_file_test},
  {"pkt get subnet mask", pkt_get_subnet_mask_test},
  {"pkt get address", pkt_get_address_test},
  {"pkt get router", pkt_get_router_test},
  {"pkt get domain name", pkt_get_domain_name_test},
  CU_TEST_INFO_NULL,
};


#endif // TEST_PKT_ARRAY_H
