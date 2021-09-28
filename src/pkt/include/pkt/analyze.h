#include "dhcp.h"
#include "validate.h"
#include <errno.h>

#if !defined(PKT_ANALYZE_H)
#define PKT_ANALYZE_H

#define DHCP_MAGIC_COOKIE_SIZE               4

#define PKT_IP_MAX_LEN                      16  /* len (255.255.255.255) == 15(+ 1 for avoiding undefined bahavior) */

#define PKT_ADDR_MAX_LEN                    18  /* len (FF:FF:FF:FF:FF:FF) == 17(+ 1 for avoiding undefined bahavior) */

#define HEX                                 16

#define PKT_IP_ADDR_LEASE_TIME_LEN          4

enum dhcpMessageTypes
{
  DHCPDISCOVER = 1,       /* RFC 2132 */
  DHCPOFFER,              /* RFC 2132 */
  DHCPREQUEST,            /* RFC 2132 */
  DHCPDECLINE,            /* RFC 2132 */
  DHCPACK,                /* RFC 2132 */
  DHCPNAK,                /* RFC 2132 */
  DHCPRELEASE,            /* RFC 2132 */
  DHCPINFORM,             /* RFC 2132 */
  DHCPFORCERENEW,         /* RFC 3203 */
  DHCPLEASEQUERY,               /* RFC 4388 */
  DHCPLEASEUNASSIGNED,          /* RFC 4388 */
  DHCPLEASEUNKNOWN,             /* RFC 4388 */
  DHCPLEASEACTIVE,              /* RFC 4388 */
  DHCPBULKLEASEQUERY,           /* RFC 6926 */
  DHCPLEASEQUERYDONE,           /* RFC 6926 */
  DHCPACTIVELEASEQUERY,         /* RFC 7724 */
  DHCPLEASEQUERYSTATUS,         /* RFC 7724 */
  DHCPTLS,                      /* RFC 7724 */
  DHCPUNKNOW
};

enum dhcpOptions
{
  OPTION_PAD = 0,
  OPTION_SUBNET_MASK,               /* RFC 950 */
  OPTION_TIME_OFFSET,
  OPTION_ROUTER,
  OPTION_TIME_SERVER,               /* RFC 868 */
  OPTION_NS,
  OPTION_DNS,                 /* RFC 1035 */
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
  /* Numbered */
  OPTION_TFTP_SERVER_NAME = 66,
  OPTION_BOOT_FILE,
  OPTION_HOST_AGENT_ADDR,
  OPTION_USER_CLASS_INFO = 77,
  OPTION_RELAY_AGENT_INFO = 82,
  OPTION_DNS_DOMAIN_SEARCH_LIST = 119,
  OPTION_END = 255,
};

enum pktErr
{
  PKT_RET_OPT_NOTFOUNT,
  PKT_RET_INVALID_LEN,
  PKT_RET_FAILURE = -1,
  PKT_RET_SUCCESS = 0
};

enum pktAddressType
{
  PKT_ADDR_TYPE_IP,
  PKT_ADDR_TYPE_MAC,
};

typedef bool (*pktValidator_t) (void *);

char *pktGetMagicCookie (pktDhcpPacket_t *pkt);

void pktPrintMagicCookie (pktDhcpPacket_t *pkt);

enum dhcpMessageTypes pktGetDhcpMessageType (pktDhcpPacket_t *pkt);

struct in_addr *pktGetRequestedIpAddress (pktDhcpPacket_t *pkt);

char *pktGetHostName (pktDhcpPacket_t *pkt);

pktParameterRequestList_t *pktGetParameterList (pktDhcpPacket_t *pkt);

struct in_addr *pktGetServerIdentifier (pktDhcpPacket_t *pkt);

char *pktAddrStr2hex (char *addr, size_t len, char *separator, int type);

char *pktAddrHex2str (char *addr, size_t len, char separator, int type);

char *pktMacStr2hex (char *mac);

char *pktMacHex2str (char *hexMac);

char *pktIpHex2str (char *ip);

char *pktIpStr2hex (char *ip);

char *pktGetIpAddressLeaseTime (pktDhcpPacket_t *pkt);

long long pktLeaseTimeHex2long (char *time);

char *pktLeaseTimeLong2hex (long long time);

struct in_addr *pktGetSubnetMask (pktDhcpPacket_t *pkt);

struct in_addr *pktGetAddress (pktDhcpPacket_t *pkt,
                               pktValidator_t validator);

struct in_addr *pktGetRouter (pktDhcpPacket_t *pkt);

char *pktGetDomainName (pktDhcpPacket_t *pkt);

char *pktGetString (pktDhcpPacket_t *pkt, pktValidator_t validator);

char *pktGetMessage (pktDhcpPacket_t *pkt);

#endif
