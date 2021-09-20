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
pkt_get_magic_cookie (dhcp_packet_t *pkt)
{
  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  char *cookie = (char *)malloc (sizeof (char) * DHCP_MAGIC_COOKIE_SIZE);

  if (cookie == NULL && DHCP_MAGIC_COOKIE_SIZE > 0)
    return NULL;

  strncpy (cookie, opt->cookie, 4);

  cookie[4] = 0;

  return cookie;
}

void
pkt_print_magic_cookie (dhcp_packet_t *pkt)
{
  char *cookie = pkt_get_magic_cookie (pkt);

  for (size_t i = 0; i < DHCP_MAGIC_COOKIE_SIZE; i++)
    printf ("%x", cookie[i] & 0xff);
}

enum dhcpMessageTypes
pkt_get_dhcp_message_type (dhcp_packet_t *pkt)
{
  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  messageType_t *msgType = NULL;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_msg_type_option_valid ((messageType_t *)&opt->opts[i]))
        msgType = (messageType_t *)&opt->opts[i];
    }

  return msgType != NULL ? msgType->type : DHCP_MSG_TYPE_UNKNOW;
}

struct in_addr
pkt_get_requested_ip_address (dhcp_packet_t *pkt)
{
  struct in_addr addr = {0};

  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  requestedIpAddress_t *reqIpAddrOpt = NULL;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_requested_ip_addr_option_valid ((requestedIpAddress_t *)
          &opt->opts[i]))
        reqIpAddrOpt = (requestedIpAddress_t *)&opt->opts[i];
    }

  inet_aton (reqIpAddrOpt->ip, &addr);

  return addr;
}

char *
pkt_get_host_name (dhcp_packet_t *pkt)
{
  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  hostName_t *hostNameOpt = NULL;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_host_name_option_valid ((hostName_t *)&opt->opts[i]))
        {
          hostNameOpt = (hostName_t *)&opt->opts[i];

          break;
        }
    }

  if (hostNameOpt == NULL)
    return NULL;

  char *hostname = (char *)malloc (hostNameOpt->len);

  memcpy (hostname, hostNameOpt->name,hostNameOpt->len);

  return hostname;
}