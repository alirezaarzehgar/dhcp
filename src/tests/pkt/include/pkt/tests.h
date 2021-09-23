#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/fcntl.h>

#include "pkt/core.h"

#include <CUnit/Basic.h>

#if !defined(TESTS_PKT_TESTS_H)
#define TESTS_PKT_TESTS_H

int init_suite_pkt();

int cleanup_suite_pkt();

void pkt_get_magic_cookie_test();

void pkt_get_requested_ip_address_test();

void pkt_get_dhcp_message_type_test();

void pkt_get_host_name_test();

void pkt_get_parameter_list_test();

void pkt_get_server_identifier_test();

void pkt_ip_hex2str_test();

void pkt_ip_str2hex_test();

void pkt_get_ip_address_lease_time_test();

void pkt_offer_file_test();

void pkt_lease_time_hex2long_test();

void pkt_lease_time_long2hex_test();

void pkt_get_subnet_mask_test();

void pkt_get_address_test();

void pkt_get_router_test();

void pkt_get_domain_name_test();

void pkt_get_string_test();

#endif // TESTS_PKT_TESTS_H
