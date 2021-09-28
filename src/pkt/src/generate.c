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
pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer,
             pktGenCallback_t *blocks, size_t blocksLen, pktGenCallback_t *options,
             size_t optionsLen)
{
  char *discoveryCookie;

  if (!pktIsDiscoveryPktValidForOffer (discovery))
    return PKT_RET_FAILURE;

  /**
   * @brief Apply default offer fields
   *
   */
  pktGenFieldHardwareLen (offer, PKT_HLEN);

  pktGenFieldHardwareType (offer, PKT_HTYPE_ETHERNET);

  if (blocks)
    {
      for (size_t i = 0; i < blocksLen; i++)
        blocks[i].func (offer, blocks[i].param);
    }

  /**
   * @brief Apply necessary offer fileds
   *
   */
  pktGenFieldOperationCode (offer, PKT_MESSAGE_TYPE_BOOT_REPLY);

  pktGenFieldClientMacAddress (offer, pktMacHex2str (discovery->chaddr));

  pktGenFieldTransactionId (offer, discovery->xid);

  /**
  * @brief Apply default offer options
  *
  */
  pktGenOptInit();

  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)&offer->options;

  discoveryCookie = pktGetMagicCookie (discovery);

  pktGenOptMagicCookie (opt, discoveryCookie);

  pktGenOptDhcpMsgType (opt, DHCPOFFER);

  /**
   * @brief Iterate and run all option functions
   *
   */
  if (options)
    {
      for (size_t i = 0; i < optionsLen; i++)
        options[i].func (opt, options[i].param);
    }

  /**
  * @brief Apply necessary offer options
  *
  */

  pktGenOptEnd (opt);

  return PKT_RET_SUCCESS;
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

  return PKT_RET_SUCCESS;
}

int
pktGenNak (void *unused /* TODO any parameter sets on future */,
           pktDhcpPacket_t *nak)
{
  /* get error message */

  /* TODO - get error message */

  /* get extra option */

  /* TODO - get extra option */

  return PKT_RET_SUCCESS;
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
pktGenOptAddr (pktDhcpOptions_t *opt, char *addr, int option, size_t len)
{
  pktAddress_t address = {.option = option & 0xff, .len = len};

  size_t size = sizeof (pktAddress_t) + address.len;

  char *hexAddr = pktIpStr2hex (addr);

  if (hexAddr)
    memcpy (address.addr, hexAddr, address.len);

  memcpy (&opt->opts[currentBlock], &address, size);

  currentBlock += size;
}

void
pktGenOptDhcpServerIdentofier (pktDhcpOptions_t *opt, char *server)
{
  pktGenOptAddr (opt, server, OPTION_SERVER_IDENTIFIER, PKT_DEFAULT_ADDRESS_LEN);
}

void
pktGenOptIpAddrLeaseTime (pktDhcpOptions_t *opt, uint32_t time)
{
  char *hexTime;

  pktIpAddressLeaseTime_t ipAddrLT = {.option = OPTION_IP_ADDR_LEASE_TIME & 0xff, .len = PKT_IP_ADDR_LEASE_TIME_LEN};

  hexTime = pktLeaseTimeLong2hex (time);

  if (time)
    memcpy (ipAddrLT.time, hexTime, ipAddrLT.len);

  memcpy (&opt->opts[currentBlock], &ipAddrLT, sizeof (pktIpAddressLeaseTime_t));

  currentBlock += sizeof (pktIpAddressLeaseTime_t);
}

void
pktGenOptSubnetMask (pktDhcpOptions_t *opt, char *netmask)
{
  pktGenOptAddr (opt, netmask, OPTION_SUBNET_MASK, PKT_DEFAULT_ADDRESS_LEN);
}

void
pktGenOptRouter (pktDhcpOptions_t *opt, char *router)
{
  pktGenOptAddr (opt, router, OPTION_ROUTER, PKT_DEFAULT_ADDRESS_LEN);
}

void
pktGenOptString (pktDhcpOptions_t *opt, char *string, int option)
{
  pktString_t str = {.option = option & 0xff, .len = strlen (string)};

  size_t size = sizeof (pktDomainName_t) + str.len;

  char *name = string;

  if (name)
    memcpy (str.name, name, str.len);

  memcpy (&opt->opts[currentBlock], &str, sizeof (pktString_t) + str.len);

  currentBlock += size;
}

void
pktGenOptDomainName (pktDhcpOptions_t *opt, char *domainName)
{
  pktGenOptString (opt, domainName, OPTION_DOMAIN_NAME);
}

void
pktGenOptEnd (pktDhcpOptions_t *opt)
{
  pktEnd_t end = {.option = OPTION_END};

  memcpy (&opt->opts[currentBlock], &end, sizeof (pktEnd_t));

  currentBlock = -1;
}

void
pktGenFieldClientMacAddress (pktDhcpPacket_t *pkt, char *chaddr)
{
  if (pkt->hlen == 0)
    pkt->hlen = PKT_HLEN;

  char *hexMac = pktMacStr2hex (chaddr);

  memcpy (pkt->chaddr, hexMac, pkt->hlen);
}

void
pktGenFieldOperationCode (pktDhcpPacket_t *pkt, int op)
{
  pkt->op = op;
}

void
pktGenFieldHardwareType (pktDhcpPacket_t *pkt, int htype)
{
  pkt->htype = htype;
}

void
pktGenFieldTransactionId (pktDhcpPacket_t *pkt, int xid)
{
  pkt->xid = xid;
}

void
pktGenFieldYourIpAddress (pktDhcpPacket_t *pkt, char *yip)
{
  pkt->yiaddr.s_addr = inet_addr (yip);
}

void
pktGenFieldHardwareLen (pktDhcpPacket_t *pkt, int len)
{
  pkt->hlen = len;
}