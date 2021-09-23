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
pkt_is_msg_type_valid (enum dhcpMessageTypes type)
{
  int t = type & 0xff;
  return t <= DHCPTLS && t >= DHCPDISCOVER;
}

bool
pkt_is_msg_type_option_valid (pktMessageType_t *opt)
{
  return pkt_is_msg_type_valid (opt->type) &&
         opt->option == OPTION_DHCP_MSG_TYPE &&
         opt->len == 1;
}

bool
pkt_is_requested_ip_addr_option_valid (pktRequestedIpAddress_t *opt)
{
  struct in_addr *ip;

  inet_aton (opt->ip, ip);

  return opt->option == OPTION_REQUESTED_IP_ADDR &&
         (opt->len != ip->s_addr || ip->s_addr == 0);
}

bool
pkt_is_valid_string (pktString_t *opt, int option)
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
pkt_is_host_name_option_valid (pktString_t *opt)
{
  return pkt_is_valid_string (opt, OPTION_HOST_NAME);
}

bool
pkt_is_parameter_list_valid (pktParameterRequestList_t *opt)
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
pkt_is_address_valid (pktAddress_t *opt, int option,  int max)
{
  for (size_t i = 0; i < opt->len; i++)
    if (opt->addr[i] & 0xff < 0 || opt->addr[i] & 0xff > max)
      return false;

  return opt->option == option & 0xff && opt->len == PKT_DEFAULT_ADDRESS_LEN;
}

bool
pkt_is_valid_server_identifier (pktServerIdentifier_t *opt)
{
  return pkt_is_address_valid ((pktAddress_t *)opt, OPTION_SERVER_IDENTIFIER,
                               PKT_MAX_IP_SEGMENT_LEN);
}

bool
pkt_is_ip_address_lease_time_option_valid (pktIpAddressLeaseTime_t *opt)
{
  return opt->option == OPTION_IP_ADDR_LEASE_TIME & 0xff
         && opt->len == PKT_DEFAULT_ADDRESS_LEN;
}

bool
pkt_is_valid_subnet_mask (pktSubnetMask_t *opt)
{
  return pkt_is_address_valid ((pktAddress_t *)opt, OPTION_SUBNET_MASK,
                               PKT_MAX_IP_SEGMENT_LEN + 1);
}

bool
pkt_is_valid_router (pktRouter_t *opt)
{
  return pkt_is_address_valid ((pktAddress_t *)opt, OPTION_ROUTER,
                               PKT_MAX_IP_SEGMENT_LEN);
}

bool
pkt_is_domain_name_option_valid (pktString_t *opt)
{
  return pkt_is_valid_string (opt, OPTION_DOMAIN_NAME);
}