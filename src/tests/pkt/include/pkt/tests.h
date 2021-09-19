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

#endif // TESTS_PKT_TESTS_H
