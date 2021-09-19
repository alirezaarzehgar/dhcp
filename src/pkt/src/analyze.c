/**
 * @file analyze.c
 * @author alireza arzehgar (alirezaarzehgar82@gmail.com)
 * @brief
 * @version 0.1
 * @date 2021-09-19
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/analyze.h"

char *
get_magic_cookie (dhcp_packet_t *pkt)
{
  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  char *cookie = (char *)malloc (sizeof (char) * DHCP_MAGIC_COOKIE_SIZE);

  strncpy (cookie, opt->cookie, 4);

  cookie[4] = 0;

  return cookie;
}

void
print_magic_cookie (dhcp_packet_t *pkt)
{
  char *cookie = get_magic_cookie (pkt);

  for (size_t i = 0; i < DHCP_MAGIC_COOKIE_SIZE; i++)
    printf ("%x", cookie[i] & 0xff);
}

enum dhcpMessageTypes
get_dhcp_message_type (dhcp_packet_t *pkt)
{
  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  if (opt->messageType.option != OPTION_DHCP_MSG_TYPE
      || opt->messageType.len != 1)
    return DHCP_MSG_TYPE_UNKNOW;

  switch (opt->messageType.type)
    {
    case DHCP_MSG_TYPE_DISCOVER:
    case DHCP_MSG_TYPE_OFFER:
    case DHCP_MSG_TYPE_REQUEST:
    case DHCP_MSG_TYPE_ACK:
    case DHCP_MSG_TYPE_DECLIENT:
    case DHCP_MSG_TYPE_NAK:
    case DHCP_MSG_TYPE_RELEASE:
      return opt->messageType.type;

    default:
      return DHCP_MSG_TYPE_UNKNOW;
    }
}

struct in_addr
get_requested_ip_address (dhcp_packet_t *pkt)
{
  struct in_addr addr;

  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  int option = opt->requestedIpAddress.option;

  size_t ipLen = opt->requestedIpAddress.len;

  size_t actulIpLen = strlen (opt->requestedIpAddress.ip);

  if (option == OPTION_REQUESTED_IP_ADDR
      && ipLen == 4 &&  actulIpLen == ipLen)
    inet_aton (opt->requestedIpAddress.ip, &addr);

  else
    addr.s_addr = 0;

  return addr;
}