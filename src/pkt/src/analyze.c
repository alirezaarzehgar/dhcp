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

enum
{
  DHCP_MSG_TYPE_DISCOVER = 1,
  DHCP_MSG_TYPE_OFFER,
  DHCP_MSG_TYPE_REQUEST,
  DHCP_MSG_TYPE_DECLIENT,
  DHCP_MSG_TYPE_ACK,
  DHCP_MSG_TYPE_NAK,
  DHCP_MSG_TYPE_RELEASE
} dhcpMessageTypes;

enum
{
  OPTION_PAD = 0,
  OPTION_SUBNET_MASK,               /* RFC 950 */
  OPTION_TIME_OFFSET,
  OPTION_ROUTER,
  OPTION_TIME_SERVER,               /* RFC 868 */
  OPTION_NS,
  OPTION_DOMAIN_NS,                 /* RFC 1035 */
  OPTION_LOG_SERVER,
  OPTION_COOKIE_SERVER,             /* RFC 865 */
  OPTION_LRP_SERVER,                /* RFC 1179 */
  OPTION_IMPRESS_SERVER,
  OPTION_RESOUECE_LOCATION,         /* RFC 887 */
  OPTION_HOST_NAME,                 /* RFC 1035 */
  OPTION_BOOT_FILE_SIZE,
  OPTION_MERIT_DUMP_FILE,
  OPTION_DOMAIN_NAME,
  OPTION_SWAP_SERVER,
  OPTION_ROOT_PATH,
  OPTION_EXTENSION_PATH,
  OPTION_IP_FORWARDING_ED,                      /* ED = Enable/Disable */
  OPTION_NON_LOCAL_SOURCE_ROUTING_ED,           /* ED = Enable/Disable */
  OPTION_POLICY_FILTER,
  OPTION_MAX_DGRAM_REASSEMBLY_SIZE,
  OPTION_DEFAULT_IP_TTL,
  OPTION_PATH_MTU_AGING_TIMEOUT,                /* RFC 1191 */
  OPTION_PATH_MTU_PLATEAU_TABLE,                /* RFC 1191 */
  OPTION_INTERFACE_MTU,
  OPTION_ALL_SUBNETS_ARE_LOCAL,
  OPTION_BROADCAST_ADDRESS,
  OPTION_PERFORM_MASK_DISCOVERY,
  OPTION_MASK_SUPPLIER,
  OPTION_PERFORM_ROUTER_DISCOVERY,              /* RFC 1256 */
  OPTION_ROUTER_SOLOCOTIATION_ADDRESS,
  OPTION_STATIC_ROUTE,
  OPTION_TRAILER_ENCAPSULATIONS,                /* RFC 893 */
  OPTION_ARP_CACHE_TIMEOUT,
  OPTION_ETHERNET_ENCAPSULATION,                /* RFC 894, 1042,  */
  OPTION_TCP_DEFAULT_TTL,
  OPTION_TCP_KEEPALIVE_INTERVAL,
  OPTION_TCP_KEEPALIVE_GARBAGE,
  OPTION_NETWORK_INFO_SERVICE_DOMAIN,
  OPTION_NETWORK_INFO_SERVERS,
  OPTION_NTP_SERVER,
  OPTION_VENDOR_SPECIFIC_INFO,
  OPTION_NETBIOS_OVER_TCP_IP_NS,                            /* RFC 1001/1002 */
  OPTION_NETBIOS_OVER_TCP_IP_DGRAM_DISTRIBUTION_SERVER,     /* RFC 1001/1002 */
  OPTION_NETBIOS_OVER_TCP_IP_NODE_TYPE,         /* B-node=0x1, P-node=0x2, M-node=0x4, H-node=0x8 */
  OPTION_NETBIOS_OVER_SCOPE,                    /* RFC 1001/1002 */
  OPTION_XWINDOW_SYSTEM_FONT_SERVER,
  OPTION_XWINDOW_SYSTEM_DM,                     /* DM=Display Manager */
  OPTION_REQUESTED_IP_ADDR,
  OPTION_IP_ADDR_LEASE_TIME,
  OPTION_OVERLOAD,
  OPTION_DHCP_MSG_TYPE,         /* DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE */
  OPTION_SERVER_IDENTIFIER,
  OPTION_PARAMETER_REQUERSTED,
  OPTION_MSG,
  OPTION_MAX_DHCP_MSG_SIZE,
  OPTION_RENEWAL_T1_TIME_VALUE,
  OPTION_REBINDING_T2_TIME_VALUE,
  OPTION_CLASS_IDENTIFIER,
  OPTION_CLIENT_IDENTIFIER,
  OPTION_END = 255,
} dhcpOptions;

char *
get_magic_cookie (dhcp_packet_t *pkt)
{
  dhcp_options_t *opt = (dhcp_options_t *)pkt->options;

  opt->cookie[4] = 0;

  return opt->cookie;
}

void
print_magic_cookie (dhcp_packet_t *pkt)
{
  char *cookie = get_magic_cookie (pkt);

  for (size_t i = 0; i < DHCP_MAGIC_COOKIE_SIZE; i++)
    printf ("%x", cookie[i] & 0xff);
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