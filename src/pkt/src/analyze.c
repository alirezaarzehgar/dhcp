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

  /* +1 for nul */
  char *cookieForReturn = (char *)malloc (sizeof (char) *
                                          DHCP_MAGIC_COOKIE_SIZE + 1);

  if (!cookieForReturn && DHCP_MAGIC_COOKIE_SIZE > 0)
    return NULL;

  /* +1 for nul */
  char cookie[DHCP_MAGIC_COOKIE_SIZE + 1];

  memcpy (cookie, opt->cookie, DHCP_MAGIC_COOKIE_SIZE);

  cookie[DHCP_MAGIC_COOKIE_SIZE] = '\0';

  memcpy (cookieForReturn, cookie, DHCP_MAGIC_COOKIE_SIZE);

  bzero (cookie, DHCP_MAGIC_COOKIE_SIZE);

  return cookieForReturn;
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

  char *hostname;

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

  /* +1 for nul */
  hostname = (char *)malloc (hostNameOpt->len + 1);

  if (!hostname && hostNameOpt->len > 0)
    return NULL;

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

  if (!list)
    return NULL;

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

  if (!retIp)
    return NULL;

  char *tmp;

  int index = 0;

  memcpy (tmpIp, ip, PKT_IP_MAX_LEN);

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
pkt_get_address (pktDhcpPacket_t *pkt, pktValidator_t validator)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktAddress_t *address = NULL;

  struct in_addr *addr = (struct in_addr *)malloc (sizeof (struct in_addr));

  if (!addr)
    return 0;

  char *ip;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (validator ((pktAddress_t *)&opt->opts[i]))
        {
          address = (pktAddress_t *)&opt->opts[i];
          break;
        }
    }

  if (!address)
    return NULL;

  ip = pkt_ip_hex2str (address->addr);

  addr->s_addr = inet_addr (ip);

  return addr;
}

struct in_addr *
pkt_get_server_identifier (pktDhcpPacket_t *pkt)
{
  return pkt_get_address (pkt, (pktValidator_t)pkt_is_valid_server_identifier);
}

char *
pkt_get_ip_address_lease_time (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktIpAddressLeaseTime_t *leaseTime = NULL;

  char *time = (char *)malloc (sizeof (char) * 4);

  if (!time)
    return NULL;

  for (size_t i = 0; i < DHCP_PACKET_MAX_LEN; i++)
    {
      if (pkt_is_ip_address_lease_time_option_valid ((pktIpAddressLeaseTime_t *)
          &opt->opts[i]))
        {
          leaseTime = (pktIpAddressLeaseTime_t *)&opt->opts[i];
          break;
        }
    }

  if (!leaseTime)
    return NULL;

  memcpy (time, leaseTime->time, leaseTime->len);

  return time;
}

long long
pkt_lease_time_hex2long (char *time)
{
  int maxLen = 8;

  char tmp[maxLen];

  /* convert 4 time segment to hex string */
  snprintf (tmp, maxLen + 1, "%02x%02x%02x%02x", time[0] & 0xff, time[1] & 0xff,
            time[2] & 0xff, time[3] & 0xff);

  return strtol (tmp, NULL, HEX);
}

char *
pkt_lease_time_long2hex (long long time)
{
  char *timeHexForReturn = (char *)malloc (sizeof (char) * 4);

  if (!timeHexForReturn)
    return NULL;

  char timeHex[4];

  char hexFormat[8];

  char tmp[2];

  snprintf (hexFormat, 9, "%08x", time);

  for (size_t i = 0; i < 4; i++)
    {
      strncpy (tmp, &hexFormat[i * 2], 2);

      tmp[i * 2 + 2] = '\0';

      timeHex[i] = strtol (tmp, NULL, HEX);
    }

  memcpy (timeHexForReturn, timeHex, 4);

  return timeHexForReturn;
}

struct in_addr *
pkt_get_subnet_mask (pktDhcpPacket_t *pkt)
{
  return pkt_get_address (pkt, (pktValidator_t)pkt_is_valid_subnet_mask);
}

