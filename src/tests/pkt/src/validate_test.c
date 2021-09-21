/**
 * @file validate.c
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2021-09-20
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/validate_test.h"
#include "pkt/validate.h"

void
pkt_is_msg_type_valid_test()
{
  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCPDISCOVER));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCPACK));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCPNAK));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCPOFFER));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCPRELEASE));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCPREQUEST));

  CU_ASSERT_FALSE (pkt_is_msg_type_valid (DHCPUNKNOW));

  CU_ASSERT_FALSE (pkt_is_msg_type_valid (423));
}

void
pkt_is_msg_type_option_valid_test()
{
  pktMessageType_t opt = {.len = 1, .type = DHCPDISCOVER, .option = OPTION_DHCP_MSG_TYPE};

  CU_ASSERT_TRUE (pkt_is_msg_type_option_valid (&opt));

  opt.len = 12;

  CU_ASSERT_FALSE (pkt_is_msg_type_option_valid (&opt));

  opt.len = 1;

  opt.type = DHCPUNKNOW;

  CU_ASSERT_FALSE (pkt_is_msg_type_option_valid (&opt));

  opt.type = DHCPDISCOVER;

  opt.option = OPTION_COOKIE_SERVER;

  CU_ASSERT_FALSE (pkt_is_msg_type_option_valid (&opt));
}

void
pkt_is_requested_ip_addr_option_valid_test()
{
  pktRequestedIpAddress_t opt = {.len = 0, .option = OPTION_REQUESTED_IP_ADDR};

  CU_ASSERT_TRUE (pkt_is_requested_ip_addr_option_valid (&opt));
}

void
pkt_is_host_name_option_valid_test()
{
#define SAME_TEST(VALUE) CU_ASSERT_##VALUE (pkt_is_host_name_option_valid (hname))

  char buf[200];

  pktHostName_t *hname = (pktHostName_t *)buf;

  hname->option = OPTION_HOST_NAME & 0xff;

  hname->len = 3;

  strncpy (hname->name, "ali", hname->len);

  SAME_TEST (TRUE);

  hname->len = 16;

  SAME_TEST (FALSE);

  bzero (hname->name, hname->len);

  memcpy (hname->name, "", 0);

  SAME_TEST (FALSE);

  hname->option = OPTION_END & 0xff;

  SAME_TEST (FALSE);
}

void
pkt_is_parameter_list_valid_test()
{
  char buf[200];

  int index = 0;

  pktParameterRequestList_t *list = (pktParameterRequestList_t *)buf;

  list->option = OPTION_PARAMETER_REQUERSTED & 0xff;

  list->list[index++] = OPTION_SUBNET_MASK;
  list->list[index++] = OPTION_BROADCAST_ADDRESS;
  list->list[index++] = OPTION_ROUTER;
  list->list[index++] = OPTION_DOMAIN_NAME;
  list->list[index++] = OPTION_DNS;
  list->list[index++] = OPTION_DNS_DOMAIN_SEARCH_LIST;

  list->len = index;

  CU_ASSERT_TRUE (pkt_is_parameter_list_valid (list));

  list->len = 12;

  CU_ASSERT_FALSE (pkt_is_parameter_list_valid (list));

  list->len = index - 1;

  CU_ASSERT_TRUE (pkt_is_parameter_list_valid (list));

  list->list[index++] = (char)500;

  list->len = index;

  CU_ASSERT_FALSE (pkt_is_parameter_list_valid (list));
}

void
pkt_is_valid_server_identifier_test()
{
  pktServerIdentifier_t *si = (pktServerIdentifier_t *)malloc (sizeof (
                                pktServerIdentifier_t));

  si->option = OPTION_SERVER_IDENTIFIER & 0xff;

  si->len = 4;

  si->ip[0] = 192;
  si->ip[1] = 168;
  si->ip[2] = 133;
  si->ip[3] = 30;

  CU_ASSERT_TRUE (pkt_is_valid_server_identifier (si));
}

