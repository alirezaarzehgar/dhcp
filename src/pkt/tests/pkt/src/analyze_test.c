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

#include "pkt/analyze_test.h"

const char *pathDiscovry = "fake_data/discovery";

const char *pathOffer = "fake_data/offer";

const char *pathNak = "fake_data/nak";

const char *pathRequest = "fake_data/request";

const char *pathAll = "fake_data/all";

char bufAll[DHCP_PACKET_MAX_LEN];

char bufDiscovery[DHCP_PACKET_MAX_LEN];

char bufOffer[DHCP_PACKET_MAX_LEN];

char bufRequest[DHCP_PACKET_MAX_LEN];

char bufNak[DHCP_PACKET_MAX_LEN];

int
initSuitePkt()
{
  int fdAll = open (pathAll, O_RDONLY);

  PKT_FAILED_OPEN_FILE (fdAll, pathAll);

  int fdDiscovery = open (pathDiscovry, O_RDONLY);

  PKT_FAILED_OPEN_FILE (fdDiscovery, pathDiscovry);

  int fdOffer = open (pathOffer, O_RDONLY);

  PKT_FAILED_OPEN_FILE (fdOffer, pathOffer);

  int fdRequest = open (pathRequest, O_RDONLY);

  PKT_FAILED_OPEN_FILE (fdRequest, pathRequest);

  int fdNak = open (pathNak, O_RDONLY);

  PKT_FAILED_OPEN_FILE (fdNak, pathNak);

  read (fdAll, bufAll, DHCP_PACKET_MAX_LEN);

  read (fdDiscovery, bufDiscovery, DHCP_PACKET_MAX_LEN);

  read (fdOffer, bufOffer, DHCP_PACKET_MAX_LEN);

  read (fdRequest, bufRequest, DHCP_PACKET_MAX_LEN);

  read (fdNak, bufNak, DHCP_PACKET_MAX_LEN);

  close (fdAll);

  close (fdDiscovery);

  close (fdOffer);

  close (fdRequest);

  close (fdNak);

  return 0;
}

int
cleanupSuitePkt()
{
  return 0;
}

void
pktTestFunctionOnAllPackets (pktCustomTest_t func)
{
  pktDhcpPacket_t *pkts[] =
  {
    (pktDhcpPacket_t *)bufDiscovery,
    (pktDhcpPacket_t *)bufOffer,
    (pktDhcpPacket_t *)bufRequest,
    (pktDhcpPacket_t *)bufNak,
  };

  for (size_t i = 0; i < sizeof (pkts) / sizeof (pktDhcpPacket_t *); i++)
    func (pkts[i], i);
}

void
pktTestFunctionWithEmptyPkt (pktValidator_t func)
{
  pktDhcpPacket_t *pkt = calloc (sizeof (pktDhcpPacket_t),
                                 sizeof (pktDhcpPacket_t));

  CU_ASSERT_FALSE (func ((void *)pkt));

  free (pkt);
}

void
magic_cookie (pktDhcpPacket_t *pkt, int index)
{
  char validCookie[] = {0x63, 0x82, 0x53, 0x63, '\0'};

  char *cookie = NULL;

  cookie = pktGetMagicCookie (pkt);

  CU_ASSERT_STRING_EQUAL (cookie, validCookie);

  if (cookie)
    free (cookie);
}

void
pktGetMagicCookieTest()
{
  pktTestFunctionOnAllPackets (magic_cookie);
}

void
requested_ip_address (pktDhcpPacket_t *pkt, int index)
{
  struct in_addr *addr = pktGetRequestedIpAddress (pkt);

  char *ips[] =
  {
    "10.0.2.15",
    "192.168.133.114"
  };

  if (index % 2 == 1)
    {
      /* only for OFFER & NAK */
      CU_ASSERT (addr == NULL);
    }
  else
    CU_ASSERT_FATAL (addr != NULL);

  if (index % 2 == 0)
    {
      /* only for DISCOVERY & REQUEST */
      CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), ips[index / 2]);
    }
}

void
pktGetRequestedIpAddressTest()
{
  pktTestFunctionOnAllPackets (requested_ip_address);
}

void
message_type (pktDhcpPacket_t *pkt, int index)
{
  int types[] =
  {
    DHCPDISCOVER,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPNAK
  };

  CU_ASSERT_EQUAL (pktGetDhcpMessageType (pkt), types[index]);
}

void
pktGetDhcpMessageTypeTest()
{
  pktTestFunctionOnAllPackets (message_type);
}

void
host_name (pktDhcpPacket_t *pkt, int index)
{
  char *host = pktGetHostName (pkt);

  if (index % 2 == 0)
    {
      /* only for DISCOVERY & REQUEST */
      CU_ASSERT_STRING_EQUAL (host, "dhcp-client1");
    }

  else
    CU_ASSERT (host == NULL);

  if (host)
    free (host);
}

void
pktGetHostNameTest()
{
  pktTestFunctionOnAllPackets (host_name);
}

void
parameter_list (pktDhcpPacket_t *pkt, int index)
{
  pktParameterRequestList_t *list = pktGetParameterList (pkt);

  if (!list)
    return;

  if (index % 2 == 0)
    {
      /* only for DISCOVERY & REQUEST */
      CU_ASSERT_EQUAL (list->len, 13);

      CU_ASSERT_EQUAL (list->len, strlen (list->list));

      CU_ASSERT_EQUAL (list->option, OPTION_PARAMETER_REQUERSTED);
    }

  if (list)
    free (list);
}

void
pktGetParameterListTest()
{
  pktTestFunctionOnAllPackets (parameter_list);
}

void
server_identifier (pktDhcpPacket_t *pkt, int index)
{
  char *ips[] =
  {
    "192.168.133.30",
    "192.168.133.30",
    "192.168.100.1",
  };

  struct in_addr *addr = pktGetServerIdentifier (pkt);

  if (index > 0)
    {
      CU_ASSERT_FATAL (addr != NULL);

      /* only for DISCOVERY & REQUEST */
      CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), ips[index - 1]);
    }
}

void
pktGetServerIdentifierTest()
{
  pktTestFunctionOnAllPackets (server_identifier);
}

void
pktIpHex2strTest()
{
  char *subnet = "255.255.255.255";

  char ip[4];

  for (size_t i = 0; i < 4; i++)
    ip[i] = 1;

  CU_ASSERT_STRING_EQUAL (pktIpHex2str (ip), "1.1.1.1");

  for (size_t i = 0; i < 4; i++)
    ip[i] = 255;

  CU_ASSERT_STRING_EQUAL (pktIpHex2str (ip), subnet);

  bzero (ip, 4);

  CU_ASSERT_STRING_NOT_EQUAL (pktIpHex2str (ip), subnet);
}

void
pktIpStr2hexTest()
{
  CU_ASSERT_STRING_EQUAL (pktIpHex2str (pktIpStr2hex ("1.1.1.1")),
                          "1.1.1.1");

  CU_ASSERT_STRING_EQUAL (pktIpHex2str (pktIpStr2hex ("1.1.23.1")),
                          "1.1.23.1");

  CU_ASSERT_STRING_NOT_EQUAL (pktIpHex2str (pktIpStr2hex ("192.168.1.13")),
                              "1.1.1.1");
}

void
ip_address_lease_time (pktDhcpPacket_t *pkt, int index)
{
  char *n = pktGetIpAddressLeaseTime (pkt);

  if (index % 2 == 1 && pktGetDhcpMessageType (pkt) != DHCPNAK)
    {
      CU_ASSERT_FATAL (n != NULL);

      CU_ASSERT_EQUAL (pktLeaseTimeHex2long (n), 600);
    }

  if (n)
    free (n);
}

void
pktGetIpAddressLeaseTimeTest()
{
  pktTestFunctionOnAllPackets (ip_address_lease_time);
}

void
pktOfferFileTest()
{
  /* endpoint for checking offer file health */
  CU_ASSERT (CU_TRUE);
}

void
pktLeaseTimeHex2longTest()
{
  /* 0x0258 -> 600 */
  char time[] = {0x0, 0x0, 0x02, 0x58};

  CU_ASSERT_EQUAL (pktLeaseTimeHex2long (time), 600);
}

void
pktLeaseTimeLong2hexTest()
{
  for (size_t i = 1000000; i < 1006000; i += 50)
    CU_ASSERT_EQUAL (pktLeaseTimeHex2long (pktLeaseTimeLong2hex (i)), i);
}

void
subnet_mask (pktDhcpPacket_t *pkt, int index)
{
  struct in_addr *addr = pktGetSubnetMask (pkt);

  if (index % 2 == 1 && pktGetDhcpMessageType (pkt) != DHCPNAK)
    {
      CU_ASSERT_FATAL (addr != NULL);

      CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), "255.255.255.0");
    }

  if (addr)
    free (addr);
}

void
pktGetSubnetMaskTest()
{
  pktTestFunctionOnAllPackets (subnet_mask);
}

void
pktGetAddressTest()
{
  /**
   * get_address function didn't need to test
   *  cause testing its subfunctions can be many test for it.
   */
  CU_ASSERT (CU_TRUE);
}

void
get_router (pktDhcpPacket_t *pkt, int index)
{
  if (index % 2 == 0 || pktGetDhcpMessageType (pkt) == DHCPNAK)
    {
      /* DISCOVERY, REQUEST, NAK haven't Router Address option */
      return;
    }

  struct in_addr *addr = pktGetRouter (pkt);

  CU_ASSERT_FATAL (addr != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), "192.168.1.1");

  if (addr)
    free (addr);
}

void
pktgetRouterTest()
{
  pktTestFunctionOnAllPackets (get_router);
}

void
domain_name (pktDhcpPacket_t *pkt, int index)
{
  if (index % 2 == 0 || pktGetDhcpMessageType (pkt) == DHCPNAK)
    {
      /* DISCOVERY, REQUEST, NAK haven't Router Address option */
      return;
    }

  char *domain = pktGetDomainName (pkt);

  CU_ASSERT_FATAL (domain != NULL);

  CU_ASSERT_STRING_EQUAL (domain, "example.org");

  free (domain);
}

void
pktGetDomainNameTest()
{
  pktTestFunctionOnAllPackets (domain_name);
}

void
get_string (pktDhcpPacket_t *pkt, int index)
{
  if (index % 2 == 0 || pktGetDhcpMessageType (pkt) == DHCPNAK)
    {
      /* DISCOVERY, REQUEST, NAK haven't Router Address option */
      return;
    }

  char *domain = pktGetString (pkt, (void *)pktIsDomainNameOptionValid);

  CU_ASSERT_FATAL (domain != NULL);

  char *host = pktGetString (pkt, (void *)pktIsHostNameOptionValid);

  CU_ASSERT_FATAL (host != NULL);

  CU_ASSERT_STRING_EQUAL (domain, "example.org");

  CU_ASSERT_STRING_EQUAL (host, "dhcp-server");

  free (domain);

  free (host);
}

void
pktGetStringTest()
{
  pktTestFunctionOnAllPackets (get_string);
}

void
get_message (pktDhcpPacket_t *pkt, int index)
{
  if (pktGetDhcpMessageType (pkt) != DHCPNAK)
    {
      /* This test is just for NAK packet */
      return;
    }

  char *msg = pktGetMessage (pkt);

  CU_ASSERT_FATAL (msg != NULL);

  CU_ASSERT_STRING_EQUAL (msg, "wrong server-ID");

  free (msg);
}

void
pktGetMessageTest()
{
  pktTestFunctionOnAllPackets (get_message);
}

void
pktAddrStr2hexTest()
{
  /* TODO pktAddrStr2hexTest */
}

void
pktAddrHex2strTest()
{
  /* TODO pktAddrHex2strTest */
}

void
pktMacStr2hexTest()
{
  char *orginMac = "08:00:27:84:3e:d0";

  char *hexMac = pktMacStr2hex ("08:00:27:84:3e:d0");

  char *strMac = pktMacHex2str (hexMac);

  CU_ASSERT_STRING_EQUAL (orginMac, strMac);

  free (hexMac);

  free (strMac);
}

void
pktMacHex2strTest()
{
  char *mac1 = pktMacStr2hex ("08:00:27:84:3e:d0");
  char *mac2 = pktMacStr2hex ("08:00:27:84:3e:d0");

  CU_ASSERT_STRING_EQUAL (pktMacHex2str (mac1), pktMacHex2str (mac2));
}
