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
#define SAME_TEST(VALUE) CU_ASSERT_##VALUE (pkt_is_host_name_option_valid ((pktString_t *)hname))

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

  si->len = PKT_DEFAULT_ADDRESS_LEN;

  si->ip[0] = 192;
  si->ip[1] = 168;
  si->ip[2] = 133;
  si->ip[3] = 30;

  CU_ASSERT_TRUE (pkt_is_valid_server_identifier (si));
}

void
pkt_is_ip_address_lease_time_option_valid_test()
{
  for (size_t i = 0; i < 10; i++)
    {
      pktIpAddressLeaseTime_t lt = {.option = OPTION_IP_ADDR_LEASE_TIME & 0xff, .len = 4};

      strncpy (lt.time, pkt_lease_time_long2hex (i * rand() % 14), lt.len);

      CU_ASSERT_TRUE (pkt_is_ip_address_lease_time_option_valid (&lt));
    }
}

void
pkt_is_valid_subnet_mask_test()
{
  pktSubnetMask_t *mask = (pktSubnetMask_t *)malloc (sizeof (pktSubnetMask_t));

  mask->option = OPTION_SUBNET_MASK;

  mask->len = PKT_DEFAULT_ADDRESS_LEN;

  mask->subnet[0] = 225;
  mask->subnet[1] = 225;
  mask->subnet[2] = 225;
  mask->subnet[3] = 0;

  CU_ASSERT_TRUE (pkt_is_valid_subnet_mask (mask));
}

void
pkt_is_address_valid_test()
{
  pktSubnetMask_t *mask = (pktSubnetMask_t *)malloc (sizeof (pktSubnetMask_t));

  pktServerIdentifier_t *si = (pktServerIdentifier_t *)malloc (sizeof (
                                pktServerIdentifier_t));

  mask->option = OPTION_SUBNET_MASK;

  mask->len = PKT_DEFAULT_ADDRESS_LEN;

  mask->subnet[0] = 225;
  mask->subnet[1] = 225;
  mask->subnet[2] = 225;
  mask->subnet[3] = 0;

  si->option = OPTION_SERVER_IDENTIFIER & 0xff;

  si->len = PKT_DEFAULT_ADDRESS_LEN;

  si->ip[0] = 192;
  si->ip[1] = 168;
  si->ip[2] = 133;
  si->ip[3] = 30;

  CU_ASSERT_TRUE (pkt_is_address_valid ((pktAddress_t *)mask, OPTION_SUBNET_MASK,
                                        256));

  CU_ASSERT_TRUE (pkt_is_address_valid ((pktAddress_t *)si,
                                        OPTION_SERVER_IDENTIFIER,
                                        255));
}

void
pkt_is_valid_router_test()
{
  pktRouter_t *router = (pktRouter_t *)malloc (sizeof (pktRouter_t));

  router->option = OPTION_ROUTER;

  router->len = PKT_DEFAULT_ADDRESS_LEN;

  router->router[0] = 192;
  router->router[1] = 168;
  router->router[2] = 1;
  router->router[3] = 1;

  CU_ASSERT_TRUE (pkt_is_valid_router (router));

  router->option = OPTION_ARP_CACHE_TIMEOUT;

  CU_ASSERT_FALSE (pkt_is_valid_router (router));

  router->len = 12;

  CU_ASSERT_FALSE (pkt_is_valid_router (router));
}

void
pkt_is_valid_string_test()
{
  pktString_t *str = (pktString_t *)malloc (sizeof (pktString_t));

  str->option = OPTION_DOMAIN_NAME;

  str->len = 3;

  memcpy (str->name, "ali", str->len);

  CU_ASSERT_TRUE (pkt_is_valid_string (str, str->option));

  free (str);
}

void
pkt_is_domain_name_option_valid_test()
{
  pktDomainName_t *domain = (pktDomainName_t *)malloc (sizeof (pktDomainName_t));

  domain->option = OPTION_DOMAIN_NAME;

  domain->len = 10;

  memcpy (domain->domain, "google.org", domain->len);

  CU_ASSERT_FATAL (domain != NULL);

  CU_ASSERT_TRUE (pkt_is_domain_name_option_valid ((pktString_t*)domain));

  domain->len = 12;
  
  CU_ASSERT_FALSE (pkt_is_domain_name_option_valid ((pktString_t*)domain));

  domain->len = 10;

  domain->option = OPTION_ARP_CACHE_TIMEOUT;

  CU_ASSERT_FALSE (pkt_is_domain_name_option_valid ((pktString_t*)domain));

  free (domain);
}