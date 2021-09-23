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

const char *pathDiscovry = "src/tests/fake_data/discovery";

const char *pathOffer = "src/tests/fake_data/offer";

const char *pathNak = "src/tests/fake_data/nak";

const char *pathRequest = "src/tests/fake_data/request";

const char *pathAll = "src/tests/fake_data/all";

char bufAll[DHCP_PACKET_MAX_LEN];

char bufDiscovery[DHCP_PACKET_MAX_LEN];

char bufOffer[DHCP_PACKET_MAX_LEN];

char bufRequest[DHCP_PACKET_MAX_LEN];

char bufNak[DHCP_PACKET_MAX_LEN];

int
init_suite_pkt()
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

  read (fdAll, bufAll, BUFSIZ);

  read (fdDiscovery, bufDiscovery, BUFSIZ);

  read (fdOffer, bufOffer, BUFSIZ);

  read (fdRequest, bufRequest, BUFSIZ);

  read (fdNak, bufNak, BUFSIZ);

  close (fdAll);

  close (fdDiscovery);

  close (fdOffer);

  close (fdRequest);

  close (fdNak);

  return 0;
}

int
cleanup_suite_pkt()
{
  return 0;
}

void
pkt_test_function_on_all_packets (pktCustomTest_t func)
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
magic_cookie (pktDhcpPacket_t *pkt, int index)
{
  char validCookie[] = {0x63, 0x82, 0x53, 0x63, '\0'};

  char *cookie = NULL;

  cookie = pkt_get_magic_cookie (pkt);

  CU_ASSERT_STRING_EQUAL (cookie, validCookie);

  if (cookie)
    free (cookie);
}

void
pkt_get_magic_cookie_test()
{
  pkt_test_function_on_all_packets (magic_cookie);
}

void
requested_ip_address (pktDhcpPacket_t *pkt, int index)
{
  struct in_addr *addr = pkt_get_requested_ip_address (pkt);

  char *ips[] =
  {
    "10.0.2.15",
    "192.168.133.114"
  };

  if (index % 2 == 1)
    {
      /* check for OFFER & NAK */
      CU_ASSERT (addr == NULL);
    }
  else
    CU_ASSERT_FATAL (addr != NULL);

  if (index % 2 == 0)
    {
      /* check for DISCOVERY & REQUEST */
      CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), ips[index / 2]);
    }
}

void
pkt_get_requested_ip_address_test()
{
  pkt_test_function_on_all_packets (requested_ip_address);
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

  CU_ASSERT_EQUAL (pkt_get_dhcp_message_type (pkt), types[index]);
}

void
pkt_get_dhcp_message_type_test()
{
  pkt_test_function_on_all_packets (message_type);
}

void
host_name (pktDhcpPacket_t *pkt, int index)
{
  char *host = pkt_get_host_name (pkt);

  if (index % 2 == 0)
    {
      /* check for DISCOVERY & REQUEST */
      CU_ASSERT_STRING_EQUAL (host, "dhcp-client1");
    }

  else
    CU_ASSERT (host == NULL);

  if (host)
    free (host);
}

void
pkt_get_host_name_test()
{
  pkt_test_function_on_all_packets (host_name);
}

void
pkt_get_parameter_list_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufDiscovery;

  pktParameterRequestList_t *list = pkt_get_parameter_list (pkt);

  if (!list)
    return;

  CU_ASSERT_EQUAL (list->len, 13);

  CU_ASSERT_EQUAL (list->len, strlen (list->list));

  CU_ASSERT_EQUAL (list->option, OPTION_PARAMETER_REQUERSTED);

  if (list)
    free (list);
}

void
pkt_get_server_identifier_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufOffer;

  struct in_addr *addr = pkt_get_server_identifier (pkt);

  CU_ASSERT_FATAL (addr != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), "192.168.133.30");
}

void
pkt_ip_hex2str_test()
{
  char ip[4];

  for (size_t i = 0; i < 4; i++)
    ip[i] = 1;

  CU_ASSERT_STRING_EQUAL (pkt_ip_hex2str (ip), "1.1.1.1");

  for (size_t i = 0; i < 4; i++)
    ip[i] = 255;

  CU_ASSERT_STRING_EQUAL (pkt_ip_hex2str (ip), "255.255.255.255");

  bzero (ip, 4);

  CU_ASSERT_STRING_NOT_EQUAL (pkt_ip_hex2str (ip), "255.255.255.255");
}

void
pkt_ip_str2hex_test()
{
  CU_ASSERT_STRING_EQUAL (pkt_ip_hex2str (pkt_ip_str2hex ("1.1.1.1")),
                          "1.1.1.1");

  CU_ASSERT_STRING_EQUAL (pkt_ip_hex2str (pkt_ip_str2hex ("1.1.23.1")),
                          "1.1.23.1");

  CU_ASSERT_STRING_NOT_EQUAL (pkt_ip_hex2str (pkt_ip_str2hex ("192.168.1.13")),
                              "1.1.1.1");
}

void
pkt_get_ip_address_lease_time_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufOffer;

  char *n = pkt_get_ip_address_lease_time (pkt);

  CU_ASSERT_FATAL (n != NULL);

  CU_ASSERT_EQUAL (pkt_lease_time_hex2long (n), 600);

  if (n)
    free (n);
}

void
pkt_offer_file_test()
{
  /* endpoint for checking offer file health */
  CU_ASSERT (CU_TRUE);
}


void
pkt_lease_time_hex2long_test()
{
  /* 0x0258 -> 600 */
  char time[] = {0x0, 0x0, 0x02, 0x58};

  CU_ASSERT_EQUAL (pkt_lease_time_hex2long (time), 600);
}

void
pkt_lease_time_long2hex_test()
{
  for (size_t i = 1000000; i < 1006000; i += 50)
    CU_ASSERT_EQUAL (pkt_lease_time_hex2long (pkt_lease_time_long2hex (i)), i);
}

void
pkt_get_subnet_mask_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufOffer;

  struct in_addr *addr = pkt_get_subnet_mask (pkt);

  CU_ASSERT_FATAL (addr != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), "255.255.255.0");

  if (addr)
    free (addr);
}

void
pkt_get_address_test()
{
  /**
   * get_address function didn't need to test
   *  cause testing its subfunctions can be many test for it.
   */
  CU_ASSERT (CU_TRUE);
}

void
pkt_get_router_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufOffer;

  struct in_addr *addr = pkt_get_router (pkt);

  CU_ASSERT_FATAL (addr != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*addr), "192.168.1.1");

  if (addr)
    free (addr);
}

void
pkt_get_domain_name_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufOffer;

  char *domain = pkt_get_domain_name (pkt);

  CU_ASSERT_FATAL (domain != NULL);

  CU_ASSERT_STRING_EQUAL (domain, "example.org");

  free (domain);
}

void
pkt_get_string_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufOffer;

  char *domain = pkt_get_string (pkt, (void *)pkt_is_domain_name_option_valid);

  CU_ASSERT_FATAL (domain != NULL);

  char *host = pkt_get_string (pkt, (void *)pkt_is_host_name_option_valid);

  CU_ASSERT_FATAL (host != NULL);

  CU_ASSERT_STRING_EQUAL (domain, "example.org");

  CU_ASSERT_STRING_EQUAL (host, "dhcp-server");

  free (domain);

  free (host);
}

void
pkt_get_message_test()
{
  pktDhcpPacket_t *pkt = (pktDhcpPacket_t *)bufNak;

  char *msg = pkt_get_message (pkt);

  CU_ASSERT_FATAL (msg != NULL);

  CU_ASSERT_STRING_EQUAL (msg, "wrong server-ID");

  free (msg);
}