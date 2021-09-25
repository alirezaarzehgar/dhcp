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
}

void pktGenOfferTest ()
{
  /* TODO */
}

void pktGenAckTest ()
{
  /* TODO */
}
