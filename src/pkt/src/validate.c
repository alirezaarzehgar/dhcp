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
  switch (type & 0xff)
    {
    case DHCP_MSG_TYPE_DISCOVER:
    case DHCP_MSG_TYPE_OFFER:
    case DHCP_MSG_TYPE_REQUEST:
    case DHCP_MSG_TYPE_ACK:
    case DHCP_MSG_TYPE_DECLIENT:
    case DHCP_MSG_TYPE_NAK:
    case DHCP_MSG_TYPE_RELEASE:
      return true;

    default:
      return false;
    }
}

bool
pkt_is_msg_type_option_valid (messageType_t *opt)
{
  return !pkt_is_msg_type_valid (opt->type) ||
         opt->option != OPTION_DHCP_MSG_TYPE ||
         opt->len != 1
         ? false : true;
}

bool
pkt_is_requested_ip_addr_option_valid (requestedIpAddress_t *opt)
{
  struct in_addr *ip;
  inet_aton (opt->ip, ip);

  return opt->option != OPTION_REQUESTED_IP_ADDR ||
         ! (opt->len == ip->s_addr || ip->s_addr != 0)
         ? false : true;
}

bool
pkt_is_host_name_option_valid (hostName_t *opt)
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
pkt_is_parameter_list_valid (parameterRequestList_t *opt)
{
  return opt->option == OPTION_PARAMETER_REQUERSTED & 0xff && opt->len > 0
         && strlen (opt->list) > 0 ? true : false;
}