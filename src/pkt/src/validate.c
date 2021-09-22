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
pkt_is_host_name_option_valid (pktHostName_t *opt)
{
  if (opt->option == OPTION_HOST_NAME & 0xff && opt->len > 0)
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
pkt_is_parameter_list_valid (pktParameterRequestList_t *opt)
{
  for (size_t i = 0; i < opt->len; i++)
    if (opt->list[i] < OPTION_SUBNET_MASK || opt->list[i] > OPTION_END)
      return false;

  return opt->option == OPTION_PARAMETER_REQUERSTED & 0xff && opt->len > 0
         && strlen (opt->list) > 0;
}

bool
pkt_is_valid_server_identifier (pktServerIdentifier_t *opt)
{
  for (size_t i = 0; i < opt->len; i++)
    if (opt->ip[i] & 0xff < 0 || opt->ip[i] & 0xff > 255)
      return false;

  return opt->option == OPTION_SERVER_IDENTIFIER & 0xff && opt->len == 4
         && strlen (opt->ip) >= 4;
}

bool
pkt_is_ip_address_lease_time_option_valid (pktIpAddressLeaseTime_t *opt)
{
  return opt->option == OPTION_IP_ADDR_LEASE_TIME & 0xff && opt->len == 4;
}