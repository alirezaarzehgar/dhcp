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

/**
 * @brief In pktGenOpt function we should know current block
 * for avoiding overwriting on writed blocks.
 * We wanna add options block by block without duplication.
 *
 * -1 means to uninitialized.
 */
static uint16_t currentBlock = -1;

int
pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer)
{
  if (!pktIsDiscoveryPktValidForOffer (discovery))
    return PKT_ERR_FAILURE;

  /* Fill common BOOTP and DHCP fileds */

  /* TODO - Fill common BOOTP and DHCP fileds */

  /* Add all parameter requested list's options to offer */

  /* TODO - Add all parameter requested list's options to offer */

  return 0;
}

int
pktGenAck (pktDhcpPacket_t *request, pktDhcpPacket_t *ack)
{
  /* Check discovery packet validation */

  /* TODO - Check discovery packet validation */

  /* Fill common BOOTP and DHCP fileds */

  /* TODO - Fill common BOOTP and DHCP fileds */

  /* Add all parameter requested list's options to offer */

  /* TODO - Add all parameter requested list's options to offer */

  return 0;
}

int
pktGenNak (void *unused /* TODO any parameter sets on future */,
           pktDhcpPacket_t *nak)
{
  /* get error message */

  /* TODO - get error message */

  /* get extra option */

  /* TODO - get extra option */

  return 0;
}

void
pktGenOptInit()
{
  currentBlock = 0;
}

void
pktGenOptMagicCookie (pktDhcpOptions_t *opt, char *cookie)
{
  memcpy (&opt->opts[currentBlock], cookie, strlen (cookie));

  currentBlock += strlen (cookie);
}

void
pktGenOptDhcpMsgType (pktDhcpOptions_t *opt, int type)
{
  pktMessageType_t msgType = {.len = 1, .option = OPTION_DHCP_MSG_TYPE & 0xff, .type = type};

  memcpy (&opt->opts[currentBlock], &msgType, sizeof (pktMessageType_t));

  currentBlock += sizeof (pktMessageType_t);
}

void
pktGenOptDhcpServerIdentofier (pktDhcpOptions_t *opt, char *server)
{
  pktServerIdentifier_t serverIdentifier = {.option = OPTION_SERVER_IDENTIFIER & 0xff, .len = 4};

  size_t size = sizeof (pktServerIdentifier_t) + serverIdentifier.len;

  char *hexServ = pktIpStr2hex (server);

  if (hexServ)
    memcpy (serverIdentifier.ip, hexServ, serverIdentifier.len);

  memcpy (&opt->opts[currentBlock], &serverIdentifier, size);

  currentBlock += size;
}

void
pktGenOptIpAddrLeaseTime (pktDhcpOptions_t *opt, uint64_t time)
{
  char *hexTime;

  pktIpAddressLeaseTime_t ipAddrLT = {.option = OPTION_IP_ADDR_LEASE_TIME & 0xff, .len = 4};

  hexTime = pktLeaseTimeLong2hex (time);

  if (time)
    memcpy (ipAddrLT.time, hexTime, ipAddrLT.len);

  memcpy (&opt->opts[currentBlock], &ipAddrLT, sizeof (pktIpAddressLeaseTime_t));

  currentBlock += sizeof (pktIpAddressLeaseTime_t);
}

void
pktGenOptSubnetMask (pktDhcpOptions_t *opt, char *netmask)
{
  pktSubnetMask_t mask = {.option = OPTION_SUBNET_MASK & 0xff, .len = 4};

  size_t size = sizeof (pktSubnetMask_t) + mask.len;

  char *hexMask = pktIpStr2hex (netmask);

  if (hexMask)
    memcpy (mask.subnet, hexMask, mask.len);

  memcpy (&opt->opts[currentBlock], &mask, size);

  currentBlock += size;
}

void
pktGenOptRouter (pktDhcpOptions_t *opt, char *routerAddr)
{
  pktRouter_t router = {.option = OPTION_ROUTER & 0xff, .len = 4};

  size_t size = sizeof (pktRouter_t) + router.len;

  char *hexRouter = pktIpStr2hex (routerAddr);

  if (hexRouter)
    memcpy (router.router, hexRouter, router.len);

  memcpy (&opt->opts[currentBlock], &router, sizeof (pktRouter_t) + router.len);

  currentBlock += size;
}


void
pktGenOptDomainName (pktDhcpOptions_t *opt, char *domainName)
{
  pktDomainName_t dm = {.option = OPTION_DOMAIN_NAME & 0xff, .len = strlen (domainName)};

  size_t size = sizeof (pktDomainName_t) + dm.len;

  char *name = domainName;

  if (name)
    memcpy (dm.domain, name, dm.len);

  memcpy (&opt->opts[currentBlock], &dm, sizeof (pktDomainName_t) + dm.len);

  currentBlock += size;
}

void
pktGenOptEnd (pktDhcpOptions_t *opt)
{
  pktEnd_t end = {.option = 255};

  memcpy (&opt->opts[currentBlock], &end, sizeof (pktEnd_t));

  currentBlock = -1;
}