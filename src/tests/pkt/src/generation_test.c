/**
 * @file generation_test.c
 * @author alirezaarzehgar (alirezaarzehgar82@gmail.com)
 * @brief
 * @version 0.1
 * @date 2021-09-25
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/generation_test.h"

#include "pkt/analyze_test.h"

extern char bufAll[DHCP_PACKET_MAX_LEN];

extern char bufDiscovery[DHCP_PACKET_MAX_LEN];

extern char bufOffer[DHCP_PACKET_MAX_LEN];

extern char bufRequest[DHCP_PACKET_MAX_LEN];

extern char bufNak[DHCP_PACKET_MAX_LEN];

void
packetGenMainTest()
{
  /* Test endpoint for many test regardless specific function */

  pktDhcpPacket_t *discovery = (pktDhcpPacket_t *)bufDiscovery;

  pktDhcpPacket_t *offer = (pktDhcpPacket_t *)calloc (sizeof (pktDhcpPacket_t),
                           sizeof (pktDhcpPacket_t));

  pktDhcpOptions_t *offerOpt = (pktDhcpOptions_t *)calloc (sizeof (
                                 pktDhcpOptions_t), sizeof (pktDhcpOptions_t));

  offerOpt = (pktDhcpOptions_t *)offer->options;

  /* commons */

  unsigned char chaddr[] = { 0x08, 0x00, 0x27, 0x84, 0x3e };

  char *cookie = pktGetMagicCookie (discovery);

  CU_ASSERT_FATAL (strlen (cookie) == DHCP_MAGIC_COOKIE_SIZE);

  CU_ASSERT_FATAL (pktIsDiscoveryPktValidForOffer (discovery));

  offer->op = PKT_MESSAGE_TYPE_BOOT_REPLY;

  offer->htype = PKT_HTYPE_ETHERNET;

  offer->xid = discovery->xid;

  offer->yiaddr.s_addr = inet_addr ("192.168.133.144");

  offer->hlen = 6;

  memcpy (offer->chaddr, chaddr, offer->hlen);

  /* opts */

  pktGenOptInit();

  pktGenOptMagicCookie (offerOpt, cookie);

  pktGenOptDhcpMsgType (offerOpt, DHCPOFFER);

  pktGenOptDhcpServerIdentofier (offerOpt, "192.168.133.30");

  pktGenOptIpAddrLeaseTime (offerOpt, 600);

  pktGenOptSubnetMask (offerOpt, "255.255.255.0");

  pktGenOptRouter (offerOpt, "192.168.100.1");

  pktGenOptDomainName (offerOpt, "example.org");

  pktGenOptEnd (offerOpt);

  CU_ASSERT_EQUAL (offer->op, PKT_MESSAGE_TYPE_BOOT_REPLY);

  CU_ASSERT_EQUAL (offer->htype, PKT_HTYPE_ETHERNET);

  CU_ASSERT_STRING_EQUAL (offer->chaddr, chaddr);

  CU_ASSERT_EQUAL (offer->hlen, 6);

  CU_ASSERT_EQUAL (offer->xid, discovery->xid);

  CU_ASSERT_EQUAL (offer->yiaddr.s_addr, inet_addr ("192.168.133.144"));

  CU_ASSERT_EQUAL (pktGetDhcpMessageType (offer), DHCPOFFER);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*pktGetServerIdentifier (offer)),
                          "192.168.133.30");

  CU_ASSERT_EQUAL (pktLeaseTimeHex2long (pktGetIpAddressLeaseTime (offer)), 600);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*pktGetSubnetMask (offer)),
                          "255.255.255.0");

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*pktGetRouter (offer)), "192.168.100.1");

  CU_ASSERT_STRING_EQUAL (pktGetDomainName (offer), "example.org");
}

void
pktGenOfferTest()
{
  /* TODO pktGenOfferTest */
}

void
pktGenAckTest()
{
  /* TODO pktGenAckTest */
}

void
pktGenNakTest()
{
  /* TODO pktGenNakTest */
}