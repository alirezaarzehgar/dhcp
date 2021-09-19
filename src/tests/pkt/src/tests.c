/**
 * @file tests.c
 * @author alireza arzehgar (alirezaarzehgar82@gmail.com)
 * @brief
 * @version 0.1
 * @date 2021-09-19
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/tests.h"

const char *discovry_path = "src/tests/fake_data/discovery";

const char *magic_cookie_tmp_file = "magic_cookie.tmp";

char buf[DHCP_PACKET_MAX_LEN];

dhcp_packet_t *pkt;

int
init_suite_pkt()
{
  int fd = open (discovry_path, O_RDONLY);

  if (fd == -1)
    CU_ASSERT_FALSE (CU_TRUE);

  read (fd, buf, DHCP_PACKET_MAX_LEN);

  pkt = (dhcp_packet_t *)buf;

  close (fd);

  return 0;
}

int
cleanup_suite_pkt()
{
  return 0;
}

void
pkt_get_magic_cookie_test()
{
  char validCookie[] = {0x63, -126, 0x53, 0x63, '\0'};

  CU_ASSERT_STRING_EQUAL (get_magic_cookie(pkt), validCookie);
}

void
pkt_get_requested_ip_address_test()
{
  struct in_addr addr = {0};

  CU_ASSERT_EQUAL ((get_requested_ip_address (pkt)).s_addr, addr.s_addr);
}

void
pkt_get_dhcp_message_type_test()
{
  CU_ASSERT_EQUAL (get_dhcp_message_type (pkt), DHCP_MSG_TYPE_DISCOVER);
}