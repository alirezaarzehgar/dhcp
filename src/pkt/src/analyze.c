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
pkt_get_magic_cookie (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  char *cookie = (char *)malloc (sizeof (char) * DHCP_MAGIC_COOKIE_SIZE);

  if (!cookie && DHCP_MAGIC_COOKIE_SIZE > 0)
    return cookie;

  strncpy (cookie, opt->cookie, 4);

  cookie[4] = 0;

  return cookie;
}

void
pkt_print_magic_cookie (pktDhcpPacket_t *pkt)
{
  char *cookie = pkt_get_magic_cookie (pkt);

  for (size_t i = 0; i < DHCP_MAGIC_COOKIE_SIZE; i++)
    printf ("%x", cookie[i] & 0xff);
}

enum dhcpMessageTypes
pkt_get_dhcp_message_type (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktMessageType_t *msgType = NULL;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_msg_type_option_valid ((pktMessageType_t *)&opt->opts[i]))
        {
          msgType = (pktMessageType_t *)&opt->opts[i];
          break;
        }
    }

  return msgType ? msgType->type : DHCPUNKNOW;
}

struct in_addr
pkt_get_requested_ip_address (pktDhcpPacket_t *pkt)
{
  struct in_addr addr = {0};

  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktRequestedIpAddress_t *reqIpAddrOpt = NULL;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_requested_ip_addr_option_valid ((pktRequestedIpAddress_t *)
          &opt->opts[i]))
        {
          reqIpAddrOpt = (pktRequestedIpAddress_t *)&opt->opts[i];
          break;
        }
    }

  inet_aton (reqIpAddrOpt->ip, &addr);

  return addr;
}

char *
pkt_get_host_name (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktHostName_t *hostNameOpt = NULL;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_host_name_option_valid ((pktHostName_t *)&opt->opts[i]))
        {
          hostNameOpt = (pktHostName_t *)&opt->opts[i];
          break;
        }
    }

  if (!hostNameOpt)
    return NULL;

  char *hostname = (char *)malloc (hostNameOpt->len);

  memcpy (hostname, hostNameOpt->name, hostNameOpt->len);

  return hostname;
}

pktParameterRequestList_t *
pkt_get_parameter_list (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktParameterRequestList_t *listOpt = NULL;

  pktParameterRequestList_t *list = (pktParameterRequestList_t *)malloc (sizeof (
                                      pktParameterRequestList_t));

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_parameter_list_valid ((pktParameterRequestList_t *)&opt->opts[i]))
        {
          listOpt = (pktParameterRequestList_t *)&opt->opts[i];
          break;
        }
    }

  if (!listOpt)
    return NULL;

  memcpy (list, listOpt, sizeof (pktParameterRequestList_t));

  memcpy (list->list, listOpt->list, listOpt->len);

  return list;
}

char *
pkt_ip_hex2str (char *ip)
{
  char *tmpStr = (char *) calloc (sizeof (char) * PKT_IP_MAX_LEN, sizeof (char));

  char charHolder[5];

  for (size_t i = 0; i < 4; i++)
    {
      snprintf (charHolder, 5, "%d%c", ip[i] & 0xff, i != 3 ? '.' : '\0');

      strncat (tmpStr, charHolder, 5);
    }

  return tmpStr;
}

char *
pkt_ip_str2hex (char *ip)
{
  char tmpIp[PKT_IP_MAX_LEN];

  struct in_addr testAddr = { inet_addr (ip) };

  char *retIp = (char *)malloc (4);

  char *tmp;

  int index = 0;

  memcpy(tmpIp, ip, PKT_IP_MAX_LEN);

  if (testAddr.s_addr == 0)
    {
fail:

      retIp[0] = 0;

      retIp[1] = 0;

      retIp[2] = 0;

      retIp[3] = 0;
    }
  else
    {
      tmp = strtok (tmpIp, ".");
      if (tmp == NULL)
        goto fail;

      do
        {
          retIp[index++] = atoi (tmp);
        }
      while ((tmp = strtok (NULL, ".")) != NULL);
    }

  return retIp;
}

struct in_addr *
pkt_get_server_identifier (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktServerIdentifier_t *servIden = NULL;

  struct in_addr *addr = (struct in_addr *)malloc (sizeof (struct in_addr));

  char *ip;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_valid_server_identifier ((pktServerIdentifier_t *)&opt->opts[i]))
        {
          servIden = (pktServerIdentifier_t *)&opt->opts[i];
          break;
        }
    }

  if (!servIden)
    return NULL;

  ip = pkt_ip_hex2str (servIden->ip);

  addr->s_addr = inet_addr (ip);

  return addr;
}