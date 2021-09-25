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
pktIsMsgTypeValidTest()
{
  CU_ASSERT_TRUE (pktIsMsgTypeValid (DHCPDISCOVER));

  CU_ASSERT_TRUE (pktIsMsgTypeValid (DHCPACK));

  CU_ASSERT_TRUE (pktIsMsgTypeValid (DHCPNAK));

  CU_ASSERT_TRUE (pktIsMsgTypeValid (DHCPOFFER));

  CU_ASSERT_TRUE (pktIsMsgTypeValid (DHCPRELEASE));

  CU_ASSERT_TRUE (pktIsMsgTypeValid (DHCPREQUEST));

  CU_ASSERT_FALSE (pktIsMsgTypeValid (DHCPUNKNOW));

  CU_ASSERT_FALSE (pktIsMsgTypeValid (423));
}

void
pktIsMsgTypeOptionValidTest()
{
  pktMessageType_t opt = {.len = 1, .type = DHCPDISCOVER, .option = OPTION_DHCP_MSG_TYPE};

  CU_ASSERT_TRUE (pktIsMsgTypeOptionValid (&opt));

  opt.len = 12;

  CU_ASSERT_FALSE (pktIsMsgTypeOptionValid (&opt));

  opt.len = 1;

  opt.type = DHCPUNKNOW;

  CU_ASSERT_FALSE (pktIsMsgTypeOptionValid (&opt));

  opt.type = DHCPDISCOVER;

  opt.option = OPTION_COOKIE_SERVER;

  CU_ASSERT_FALSE (pktIsMsgTypeOptionValid (&opt));
}

void
pktIsRequestedIpAddrOptionValidTest()
{
  pktRequestedIpAddress_t opt = {.len = 0, .option = OPTION_REQUESTED_IP_ADDR};

  CU_ASSERT_TRUE (pktIsRequestedIpAddrOptionValid (&opt));
}

void
pktIsHostNameOptionValidTest()
{
#define SAME_TEST(VALUE) CU_ASSERT_##VALUE (pktIsHostNameOptionValid ((pktString_t *)hname))

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
pktIsParameterListValidTest()
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

  CU_ASSERT_TRUE (pktIsParameterListValid (list));

  list->len = index - 1;

  CU_ASSERT_TRUE (pktIsParameterListValid (list));

  list->list[index++] = (char)500;

  list->len = index;

  CU_ASSERT_FALSE (pktIsParameterListValid (list));
}

void
pktIsValidServerIdentifierTest()
{
  pktServerIdentifier_t *si = (pktServerIdentifier_t *)malloc (sizeof (
                                pktServerIdentifier_t));

  si->option = OPTION_SERVER_IDENTIFIER & 0xff;

  si->len = PKT_DEFAULT_ADDRESS_LEN;

  si->ip[0] = 192;
  si->ip[1] = 168;
  si->ip[2] = 133;
  si->ip[3] = 30;

  CU_ASSERT_TRUE (pktIsValidServerIdentifier (si));
}

void
pktIsIpAddressLeaseTimeOptionValidTest()
{
  for (size_t i = 0; i < 10; i++)
    {
      pktIpAddressLeaseTime_t lt = {.option = OPTION_IP_ADDR_LEASE_TIME & 0xff, .len = 4};

      strncpy (lt.time, pktLeaseTimeLong2hex (i * rand() % 14), lt.len);

      CU_ASSERT_TRUE (pktIsIpAddressLeaseTimeOptionValid (&lt));
    }
}

void
pktIsValidSubnetMaskTest()
{
  pktSubnetMask_t *mask = (pktSubnetMask_t *)malloc (sizeof (pktSubnetMask_t));

  mask->option = OPTION_SUBNET_MASK;

  mask->len = PKT_DEFAULT_ADDRESS_LEN;

  mask->subnet[0] = 225;
  mask->subnet[1] = 225;
  mask->subnet[2] = 225;
  mask->subnet[3] = 0;

  CU_ASSERT_TRUE (pktIsValidSubnetMask (mask));
}

void
pktIsAddressValidTest()
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

  CU_ASSERT_TRUE (pktIsAddressValid ((pktAddress_t *)mask, OPTION_SUBNET_MASK,
                                     256));

  CU_ASSERT_TRUE (pktIsAddressValid ((pktAddress_t *)si,
                                     OPTION_SERVER_IDENTIFIER,
                                     255));
}

void
pktIsValidRouterTest()
{
  pktRouter_t *router = (pktRouter_t *)malloc (sizeof (pktRouter_t));

  router->option = OPTION_ROUTER;

  router->len = PKT_DEFAULT_ADDRESS_LEN;

  router->router[0] = 192;
  router->router[1] = 168;
  router->router[2] = 1;
  router->router[3] = 1;

  CU_ASSERT_TRUE (pktIsValidRouter (router));

  router->option = OPTION_ARP_CACHE_TIMEOUT;

  CU_ASSERT_FALSE (pktIsValidRouter (router));

  router->len = 12;

  CU_ASSERT_FALSE (pktIsValidRouter (router));
}

void
pktIsValidStringTest()
{
  pktString_t *str = (pktString_t *)malloc (sizeof (pktString_t));

  str->option = OPTION_DOMAIN_NAME;

  str->len = 3;

  memcpy (str->name, "ali", str->len);

  CU_ASSERT_TRUE (pktIsValidString (str, str->option));

  free (str);
}

void
pktIsDomainNameOptionValidTest()
{
  pktDomainName_t *domain = (pktDomainName_t *)malloc (sizeof (pktDomainName_t));

  domain->option = OPTION_DOMAIN_NAME;

  domain->len = 10;

  memcpy (domain->domain, "google.org", domain->len);

  CU_ASSERT_FATAL (domain != NULL);

  CU_ASSERT_TRUE (pktIsDomainNameOptionValid ((pktString_t *)domain));

  domain->len = 12;

  CU_ASSERT_FALSE (pktIsDomainNameOptionValid ((pktString_t *)domain));

  domain->len = 10;

  domain->option = OPTION_ARP_CACHE_TIMEOUT;

  CU_ASSERT_FALSE (pktIsDomainNameOptionValid ((pktString_t *)domain));

  free (domain);
}

void
pktIsMessageValidTest()
{
  pktMessage_t *msg = (pktMessage_t *)malloc (sizeof (pktMessage_t));

  msg->option = OPTION_MSG;

  msg->len = 15;

  memcpy (msg->msg, "wrong server-ID", msg->len);

  CU_ASSERT_TRUE (pktIsMessageValid ((pktString_t *)msg));

  free (msg);
}

void
pktIsDiscoveryPktValidForOfferTest()
{
  /* TODO pktIsDiscoveryPktValidForOfferTest */
}

void
pktIsRequestPktValidForAckTest()
{
  /* TODO pktIsRequestPktValidForAckTest */
}

void
pktIsPktTypeBootReqTest()
{
  /* TODO pktIsPktTypeBootReqTest */
}

void
pktIsPktTypeBootRepTest()
{
  /* TODO pktIsPktTypeBootRepTest */
}

void
pktHaveTransactionIdTest()
{
  /* TODO pktHaveTransactionIdTest */
}

void
pktIsValidMacAddressTest()
{
  /* TODO pktIsValidMacAddressTest */
}

void
pktHaveMagicCookieTest()
{
  /* TODO pktHaveMagicCookieTest */
}

void
pktIsMsgTypeDiscoveryTest()
{
  /* TODO pktIsMsgTypeDiscoveryTest */
}

void
pktIsMsgTypeRequestTest()
{
  /* TODO pktIsMsgTypeRequestTest */
}

void
pktHaveHostNameTest()
{
  /* TODO pktHaveHostNameTest */
}

void
pktValidateWithListOfConditionsTest()
{
  /* TODO pktValidateWithListOfConditionsTest */
}

void
pktHaveParameterRequestListOptionTest()
{
  /* TODO pktHaveParameterRequestListOptionTest */
}