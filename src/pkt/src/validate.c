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
pktIsDiscoveryPktValidForOffer (pktDhcpPacket_t *pkt)
{
  /* TODO */
  return true;
}

bool
pktIsRequestPktValidForAck (pktDhcpPacket_t *pkt)
{
  /* TODO pktIsRequestPktValidForAck */
  return true;
}