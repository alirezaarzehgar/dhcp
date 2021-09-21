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

const char *all_path = "src/tests/fake_data/all";

const char *magic_cookie_tmp_file = "magic_cookie.tmp";

char buf[DHCP_PACKET_MAX_LEN];

char buf2[DHCP_PACKET_MAX_LEN];

pktDhcpPacket_t *pkt;

int size;

int
init_suite_pkt()
{
  int fd = open (discovry_path, O_RDONLY);
  int fd2 = open (all_path, O_RDONLY);
  int readed;

  if (fd == -1)
    CU_ASSERT_FALSE (CU_TRUE);

  read (fd, buf, DHCP_PACKET_MAX_LEN);

  size = read (fd2, buf2, BUFSIZ);

  if (size == -1)
    {
      CU_ASSERT_FALSE (CU_TRUE);
      return -1;
    }

  pkt = (pktDhcpPacket_t *)buf;

  close (fd);
  close (fd2);

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

  CU_ASSERT_STRING_EQUAL (pkt_get_magic_cookie (pkt), validCookie);
}

void
pkt_get_requested_ip_address_test()
{
  pktRequestedIpAddress_t *opts[5];

  int optCounter = 0;

  for (size_t i = 0; i < size; i++)
    {
      if (pkt_is_requested_ip_addr_option_valid ((pktRequestedIpAddress_t *)
          &buf2[i]))
        opts[optCounter++] = (pktRequestedIpAddress_t *)&buf2[i];
    }

  CU_ASSERT_TRUE (optCounter > 0);
}

void
pkt_get_dhcp_message_type_test()
{
  CU_ASSERT_EQUAL (pkt_get_dhcp_message_type (pkt), DHCPDISCOVER);
}

void
pkt_get_host_name_test()
{
  char *host = pkt_get_host_name (pkt);

  pktHostName_t *opts[5];

  int optCounter = 0;

  CU_ASSERT_STRING_EQUAL (host, "dhcp-server");

  for (size_t i = 0; i < size; i++)
    {
      if (pkt_is_host_name_option_valid ((pktHostName_t *)&buf2[i]))
        {
          int len;

          opts[optCounter++] = (pktHostName_t *)&buf2[i];

          len = opts[optCounter - 1]->len;

          opts[optCounter - 1]->name[len] = 0;
        }
    }

  CU_ASSERT_TRUE (optCounter > 0);

  CU_ASSERT_STRING_EQUAL (opts[0]->name, "dhcp-client1");

  CU_ASSERT_STRING_EQUAL (opts[1]->name, "dhcp-client1");
}

void
pkt_get_parameter_list_test()
{
  pktParameterRequestList_t *list = pkt_get_parameter_list (pkt);

  if (!list)
    return;

  CU_ASSERT_EQUAL (list->len, 13);

  CU_ASSERT_EQUAL (list->len, strlen (list->list));

  CU_ASSERT_EQUAL (list->option, OPTION_PARAMETER_REQUERSTED);
}

void
pkt_get_server_identifier_test()
{
  pktServerIdentifier_t *si;

  pkt_get_server_identifier ((pktDhcpPacket_t *)buf2);
}