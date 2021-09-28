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
pktGetMagicCookie (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  /* +1 for nul */
  char *cookie = (char *)malloc (sizeof (char) *
                                 DHCP_MAGIC_COOKIE_SIZE + 1);

  if (!cookie)
    return NULL;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (opt->cookie[i] != 0)
        {
          memcpy (cookie, &opt->cookie[i], DHCP_MAGIC_COOKIE_SIZE);
          break;
        }
    }

  cookie[DHCP_MAGIC_COOKIE_SIZE] = '\0';

  return cookie;
}

void
pktPrintMagicCookie (pktDhcpPacket_t *pkt)
{
  char *cookie = pktGetMagicCookie (pkt);

  for (size_t i = 0; i < DHCP_MAGIC_COOKIE_SIZE; i++)
    printf ("%02x ", cookie[i] & 0xff);
}

enum dhcpMessageTypes
pktGetDhcpMessageType (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktMessageType_t *msgType = NULL;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (pktIsMsgTypeOptionValid ((pktMessageType_t *)&opt->opts[i]))
        {
          msgType = (pktMessageType_t *)&opt->opts[i];
          break;
        }
    }

  return msgType ? msgType->type : DHCPUNKNOW;
}

struct in_addr *
pktGetRequestedIpAddress (pktDhcpPacket_t *pkt)
{
  return pktGetAddress (pkt,
                        (pktValidator_t)pktIsRequestedIpAddrOptionValid);
}

char *
pktGetString (pktDhcpPacket_t *pkt, pktValidator_t validator)
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
pktGetHostName (pktDhcpPacket_t *pkt)
{
  return pktGetString (pkt, (void *)pktIsHostNameOptionValid);
}

pktParameterRequestList_t *
pktGetParameterList (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktParameterRequestList_t *listOpt = NULL;

  pktParameterRequestList_t *list = (pktParameterRequestList_t *)malloc (sizeof (
                                      pktParameterRequestList_t));

  if (!list)
    return NULL;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (pktIsParameterListValid ((pktParameterRequestList_t *)&opt->opts[i]))
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
pktAddrHex2str (char *addr, size_t len, char separator, int type)
{
  char *tmpStr = (char *) calloc (sizeof (char) * PKT_ADDR_MAX_LEN,
                                  sizeof (char));

  char *format = type == PKT_ADDR_TYPE_IP ? "%d%c" : "%02x%c";

  char charHolder[len + 1];

  for (size_t i = 0; i < len; i++)
    {
      snprintf (charHolder, len + 1, format, addr[i] & 0xff,
                i != len - 1 ? separator : '\0');

      strncat (tmpStr, charHolder, len + 1);
    }

  return tmpStr;
}


char *
pktAddrStr2hex (char *addr, size_t len, char *separator, int type)
{
  /* Fix undefined behavior with increasing pkt addr max len*/
  char tmpAddr[PKT_ADDR_MAX_LEN];

  char *retIp = (char *)malloc (len);

  char *tmp;

  int index = 0;

  if (!retIp && len > 0)
    return NULL;

  memcpy (tmpAddr, addr, PKT_ADDR_MAX_LEN);

  tmp = strtok (tmpAddr, separator);

  do
    {
      retIp[index++] = type == PKT_ADDR_TYPE_MAC ? strtol (tmp, NULL,
                       16) : atoi (tmp);
    }
  while ((tmp = strtok (NULL, separator)) != NULL);

  return retIp;
}

char *
pktMacStr2hex (char *mac)
{
  return pktAddrStr2hex (mac, 6, ":", PKT_ADDR_TYPE_MAC);
}

char *
pktMacHex2str (char *hexMac)
{
  return pktAddrHex2str (hexMac, 6, ':', PKT_ADDR_TYPE_MAC);
}

char *
pktIpStr2hex (char *ip)
{
  return pktAddrStr2hex (ip, PKT_DEFAULT_ADDRESS_LEN, ".", PKT_ADDR_TYPE_IP);
}

char *
pktIpHex2str (char *ip)
{
  return pktAddrHex2str (ip, PKT_DEFAULT_ADDRESS_LEN, '.', PKT_ADDR_TYPE_IP);
}

struct in_addr *
pktGetAddress (pktDhcpPacket_t *pkt, pktValidator_t validator)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktAddress_t *address = NULL;

  struct in_addr *addr = (struct in_addr *)malloc (sizeof (struct in_addr));

  char *ip;

  if (!addr)
    return NULL;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (validator ((pktAddress_t *)&opt->opts[i]))
        {
          address = (pktAddress_t *)&opt->opts[i];
          break;
        }
    }

  if (!address)
    return NULL;

  ip = pktIpHex2str (address->addr);

  if (!ip)
    return NULL;

  addr->s_addr = inet_addr (ip);

  return addr;
}

struct in_addr *
pktGetServerIdentifier (pktDhcpPacket_t *pkt)
{
  return pktGetAddress (pkt, (pktValidator_t)pktIsValidServerIdentifier);
}

char *
pktGetIpAddressLeaseTime (pktDhcpPacket_t *pkt)
{
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)pkt->options;

  pktIpAddressLeaseTime_t *leaseTime = NULL;

  char *time = (char *)malloc (sizeof (char) * 4);

  if (!time)
    return NULL;

  for (size_t i = 0; i < DHCP_MIN_OPTION_LEN; i++)
    {
      if (pktIsIpAddressLeaseTimeOptionValid ((pktIpAddressLeaseTime_t *)
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
pktLeaseTimeHex2long (char *time)
{
  if (time == NULL)
    return -1;

  int maxLen = 8;

  char tmp[maxLen];

  /* convert 4 time segment to hex string */
  snprintf (tmp, maxLen + 1, "%02x%02x%02x%02x", time[0] & 0xff, time[1] & 0xff,
            time[2] & 0xff, time[3] & 0xff);

  return strtol (tmp, NULL, HEX);
}

char *
pktLeaseTimeLong2hex (long long time)
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
pktGetSubnetMask (pktDhcpPacket_t *pkt)
{
  return pktGetAddress (pkt, (pktValidator_t)pktIsValidSubnetMask);
}

struct in_addr *
pktGetRouter (pktDhcpPacket_t *pkt)
{
  return pktGetAddress (pkt, (pktValidator_t)pktIsValidRouter);
}

char *
pktGetDomainName (pktDhcpPacket_t *pkt)
{
  return pktGetString (pkt, (void *)pktIsDomainNameOptionValid);
}

char *
pktGetMessage (pktDhcpPacket_t *pkt)
{
  return pktGetString (pkt, (void *)pktIsMessageValid);
}
