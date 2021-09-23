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
  char *cookie = (char *)malloc (sizeof (char) *
                                          DHCP_MAGIC_COOKIE_SIZE + 1);

  if (!cookie && DHCP_MAGIC_COOKIE_SIZE > 0)
    return NULL;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (opt->cookie[i] != 0) {
        memcpy (cookie, &opt->cookie[i], DHCP_MAGIC_COOKIE_SIZE);
        break;
      }
    }

  cookie[DHCP_MAGIC_COOKIE_SIZE] = '\0';

  return cookie;
}

void
pkt_print_magic_cookie (pktDhcpPacket_t *pkt)
{
  char *cookie = pkt_get_magic_cookie (pkt);

  for (size_t i = 0; i < DHCP_MAGIC_COOKIE_SIZE; i++)
    printf ("%02x ", cookie[i] & 0xff);
}

enum dhcpMessageTypes
pkt_get_dhcp_message_type (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktMessageType_t *msgType = NULL;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (pkt_is_msg_type_option_valid ((pktMessageType_t *)&opt->opts[i]))
        {
          msgType = (pktMessageType_t *)&opt->opts[i];
          break;
        }
    }

  return msgType ? msgType->type : DHCPUNKNOW;
}

struct in_addr *
pkt_get_requested_ip_address (pktDhcpPacket_t *pkt)
{
  return pkt_get_address (pkt,
                          (pktValidator_t)pkt_is_requested_ip_addr_option_valid);
}

char *
pkt_get_string (pktDhcpPacket_t *pkt, pktValidator_t validator)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktString_t *stringOpt = NULL;

  char *string;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (validator ((pktString_t *)&opt->opts[i]))
        {
          stringOpt = (pktString_t *)&opt->opts[i];
          break;
        }
    }

  if (!stringOpt)
    return NULL;

  /* +1 for nul */
  string = (char *)malloc (stringOpt->len + 1);

  if (!string && stringOpt->len > 0)
    return NULL;

  memcpy (string, stringOpt->name, stringOpt->len);

  return string;
}

char *
pkt_get_host_name (pktDhcpPacket_t *pkt)
{
  return pkt_get_string (pkt, (void *)pkt_is_host_name_option_valid);
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

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
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
    goto failed;

  char *ip;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (validator ((pktAddress_t *)&opt->opts[i]))
        {
          address = (pktAddress_t *)&opt->opts[i];
          break;
        }
    }

  if (!address)
    goto failed;

  ip = pkt_ip_hex2str (address->addr);

  if (!ip)
    goto failed;

  addr->s_addr = inet_addr (ip);

  return addr;

failed:

  printf ("NULL returned!\n");
  return NULL;
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

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
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

      tmp[ (i * 2) + 2] = '\0';

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

struct in_addr *
pkt_get_router (pktDhcpPacket_t *pkt)
{
  return pkt_get_address (pkt, (pktValidator_t)pkt_is_valid_router);
}

char *
pkt_get_domain_name (pktDhcpPacket_t *pkt)
{
  return pkt_get_string (pkt, (void *)pkt_is_domain_name_option_valid);
}

char *
pkt_get_message (pktDhcpPacket_t *pkt)
{
  return pkt_get_string (pkt, (void *)pkt_is_message_valid);
}