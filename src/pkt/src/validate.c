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

#include "pkt/validate.h"

bool
pktIsMsgTypeValid (enum dhcpMessageTypes type)
{
  int t = type & 0xff;
  return t <= DHCPTLS && t >= DHCPDISCOVER;
}

bool
pktIsMsgTypeOptionValid (pktMessageType_t *opt)
{
  return pktIsMsgTypeValid (opt->type) &&
         opt->option == OPTION_DHCP_MSG_TYPE &&
         opt->len == 1;
}

bool
pktIsRequestedIpAddrOptionValid (pktRequestedIpAddress_t *opt)
{
  struct in_addr *ip;

  inet_aton (opt->ip, ip);

  return opt->option == OPTION_REQUESTED_IP_ADDR &&
         (opt->len != ip->s_addr || ip->s_addr == 0);
}

bool
pktIsValidString (pktString_t *opt, int option)
{
  if (opt->option == option & 0xff && opt->len > 0)
    {
      for (size_t i = 0; i < opt->len; i++)
        {
          if (!isprint (opt->name[i]))
            return false;
        }
      return true;
    }

  return false;
}

bool
pktIsHostNameOptionValid (pktString_t *opt)
{
  return pktIsValidString (opt, OPTION_HOST_NAME);
}

bool
pktIsParameterListValid (pktParameterRequestList_t *opt)
{
  for (size_t i = 0; i < opt->len; i++)
    if (opt->list[i] < OPTION_SUBNET_MASK || opt->list[i] > OPTION_END)
      {
        if (opt->list[i] == OPTION_END)
          break;

        return false;
      }

  return opt->option == OPTION_PARAMETER_REQUERSTED & 0xff && opt->len > 0
         && strlen (opt->list) > 0;
}

bool
pktIsAddressValid (pktAddress_t *opt, int option,  int max)
{
  for (size_t i = 0; i < opt->len; i++)
    if (opt->addr[i] & 0xff < 0 || opt->addr[i] & 0xff > max)
      return false;

  return opt->option == option & 0xff && opt->len == PKT_DEFAULT_ADDRESS_LEN;
}

bool
pktIsValidServerIdentifier (pktServerIdentifier_t *opt)
{
  return pktIsAddressValid ((pktAddress_t *)opt, OPTION_SERVER_IDENTIFIER,
                            PKT_MAX_IP_SEGMENT_LEN);
}

bool
pktIsIpAddressLeaseTimeOptionValid (pktIpAddressLeaseTime_t *opt)
{
  return opt->option == OPTION_IP_ADDR_LEASE_TIME & 0xff
         && opt->len == PKT_DEFAULT_ADDRESS_LEN;
}

bool
pktIsValidSubnetMask (pktSubnetMask_t *opt)
{
  return pktIsAddressValid ((pktAddress_t *)opt, OPTION_SUBNET_MASK,
                            PKT_MAX_IP_SEGMENT_LEN + 1);
}

bool
pktIsValidRouter (pktRouter_t *opt)
{
  return pktIsAddressValid ((pktAddress_t *)opt, OPTION_ROUTER,
                            PKT_MAX_IP_SEGMENT_LEN);
}

bool
pktIsDomainNameOptionValid (pktString_t *opt)
{
  return pktIsValidString (opt, OPTION_DOMAIN_NAME);
}

bool
pktIsMessageValid (pktString_t *opt)
{
  return pktIsValidString (opt, OPTION_MSG);
}

bool
pktIsPktTypeBootReq (pktDhcpPacket_t *pkt)
{
  return pkt->op == PKT_MESSAGE_TYPE_BOOT_REQUEST;
}

bool
pktIsPktTypeBootRep (pktDhcpPacket_t *pkt)
{
  return pkt->op == PKT_MESSAGE_TYPE_BOOT_REPLY;
}

bool
pktIsHardwareTypeEthernet (pktDhcpPacket_t *pkt)
{
  return pkt->htype = PKT_HTYPE_ETHERNET;
}

bool
pktHaveTransactionId (pktDhcpPacket_t *pkt)
{
  for (size_t i = 0; i < PKT_TRANSACTION_ID_LEN; i++)
    if (pkt->xid == PKT_HEX_NULL)
      return false;

  return true;
}

bool
pktIsValidMacAddress (pktDhcpPacket_t *pkt)
{
  for (size_t i = 0; i < pkt->hlen; i++)
    if (pkt->chaddr[i] < 0x0 || pkt->chaddr[i] > PKT_MAX_IP_SEGMENT_LEN)
      return false;

  return pkt->hlen > 0;
}

bool
pktHaveMagicCookie (pktDhcpPacket_t *pkt)
{
  char *cookie = pktGetMagicCookie (pkt);

  if (strlen (cookie) == DHCP_MAGIC_COOKIE_SIZE)
    {
      free (cookie);
      return true;
    }

  return false;
}

bool
pktIsMsgTypeDiscovery (pktDhcpPacket_t *pkt)
{
  return pktGetDhcpMessageType (pkt) == DHCPDISCOVER;
}

bool
pktIsMsgTypeRequest (pktDhcpPacket_t *pkt)
{
  return pktGetDhcpMessageType (pkt) == DHCPREQUEST;
}

bool
pktHaveHostNameOption (pktDhcpPacket_t *pkt)
{
  char *host = pktGetHostName (pkt);

  if (host)
    {
      free (host);
      return true;
    }

  return false;
}

bool
pktHaveParameterRequestListOption (pktDhcpPacket_t *pkt)
{
  pktParameterRequestList_t *list = pktGetParameterList (pkt);

  if (list)
    {
      free (list);
      return true;
    }

  return false;
}

bool
pktValidateWithListOfConditions (pktOptValidator_t *conditions,
                                 pktDhcpPacket_t *pkt, size_t len)
{
  int flag = true;

  for (size_t i = 0; i < len; i++)
    if (! (conditions[i]) (pkt))
      {
        flag = false;
        break;
      }

  return flag;
}

bool
pktIsDiscoveryPktValidForOffer (pktDhcpPacket_t *pkt)
{
  pktOptValidator_t validators[] =
  {
    pktIsPktTypeBootReq,
    pktIsHardwareTypeEthernet,
    pktIsValidMacAddress,
    pktHaveTransactionId,
    pktHaveMagicCookie,
    pktIsMsgTypeDiscovery,
    pktHaveHostNameOption,
    pktHaveParameterRequestListOption,
  };

  return pktValidateWithListOfConditions (validators, pkt,
                                          sizeof (validators) / sizeof (pktValidator_t));
}

bool
pktIsRequestPktValidForAck (pktDhcpPacket_t *pkt)
{
  pktOptValidator_t validators[] =
  {
    pktIsPktTypeBootReq,
    pktIsHardwareTypeEthernet,
    pktIsValidMacAddress,
    pktHaveTransactionId,
    pktHaveMagicCookie,
    pktIsMsgTypeRequest,
    pktHaveHostNameOption,
    pktHaveParameterRequestListOption,
  };

  return pktValidateWithListOfConditions (validators, pkt,
                                          sizeof (validators) / sizeof (pktValidator_t));
}