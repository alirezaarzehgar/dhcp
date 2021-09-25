/**
 * @file generate.c
 * @author alireza arzehgar (alirezaarzehgar82@gmail.com)
 * @brief
 * @version 0.1
 * @date 2021-09-19
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/generate.h"

int
pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer)
{
  /* Check discovery packet validation */

  /* TODO Check discovery packet validation */

  /* Fill common BOOTP and DHCP fileds */

  /* TODO Fill common BOOTP and DHCP fileds */

  /* Add all parameter requested list's options to offer */

  /* TODO Add all parameter requested list's options to offer */

  return 0;
}

int
pktGenAck (pktDhcpPacket_t *request, pktDhcpPacket_t *ack)
{
  /* Check discovery packet validation */

  /* TODO Check discovery packet validation */

  /* Fill common BOOTP and DHCP fileds */

  /* TODO Fill common BOOTP and DHCP fileds */

  /* Add all parameter requested list's options to offer */

  /* TODO Add all parameter requested list's options to offer */

  return 0;
}

int
pktGenNak (void *unused /* TODO any parameter sets on future */,
           pktDhcpPacket_t *nak)
{
  /* get error message */

  /* TODO get error message */

  /* get extra option */

  /* TODO get extra option */

  return 0;
}