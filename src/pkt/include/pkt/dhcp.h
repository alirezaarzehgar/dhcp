#if !defined(PKT_DHCP_H)
#define PKT_DHCP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DHCP_UDP_OVERHEAD (20 + /* IP header */     \
              8)   /* UDP header */
#define DHCP_SNAME_LEN    64
#define DHCP_FILE_LEN   128
#define DHCP_FIXED_NON_UDP  236
#define DHCP_FIXED_LEN    (DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
/* Everything but options. */
#define BOOTP_MIN_LEN   300

#define DHCP_MTU_MAX    1500
#define DHCP_MTU_MIN            576

#define DHCP_MAX_OPTION_LEN (DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN     (DHCP_MTU_MIN - DHCP_FIXED_LEN)

#define DHCP_PACKET_MAX_LEN     342

#define PKT_BASE_MEMBERS          u_int8_t option;  \
                                  u_int8_t len

#define PKT_IP_STRUCT_MEMBER      char ip[]

struct pktDhcpPacket
{
  u_int8_t  op;    /* 0: Message opcode/type */
  u_int8_t  htype;  /* 1: Hardware addr type (net/if_types.h) */
  u_int8_t  hlen;   /* 2: Hardware addr length */
  u_int8_t  hops;   /* 3: Number of relay agent hops from client */
  u_int32_t xid;    /* 4: Transaction ID */
  u_int16_t secs;   /* 8: Seconds since client started looking */
  u_int16_t flags;  /* 10: Flag bits */
  struct in_addr ciaddr;  /* 12: Client IP address (if already in use) */
  struct in_addr yiaddr;  /* 16: Client IP address */
  struct in_addr siaddr;  /* 18: IP address of next server to talk to */
  struct in_addr giaddr;  /* 20: DHCP relay agent IP address */
  unsigned char chaddr [16];  /* 24: Client hardware address */
  char sname [DHCP_SNAME_LEN];  /* 40: Server name */
  char file [DHCP_FILE_LEN];  /* 104: Boot filename */
  unsigned char options [DHCP_MAX_OPTION_LEN];
  /* 212: Optional parameters
  (actual length dependent on MTU). */
};

enum pktBootPMessageType
{
  PKT_MESSAGE_TYPE_BOOT_REQUEST = 1,
  PKT_MESSAGE_TYPE_BOOT_REPLY,
};

enum pktHardwareType
{
  PKT_HTYPE_ETHERNET = 1,
  PKT_HTYPE_EXPERIMENTAL,
  PKT_HTYPE_AMATUER_RADIO,
  PKT_HTYPE_PROTEON_PRONET_TOKEN_RING,
  PKT_HTYPE_CHAOS,
  PKT_HTYPE_IEEE_802,
  PKT_HTYPE_ARCNET,
  PKT_HTYPE_HYPERCHANNEL,
  PKT_HTYPE_LANSTER,
};

/* DHCP options */

struct pktMessageType
{
  PKT_BASE_MEMBERS;   /* Option (53) */
  char type;          /* RFC 2132 DHCP Message Type */
};

struct pktRequestedIpAddress
{
  PKT_BASE_MEMBERS;             /* Option 50 */
  PKT_IP_STRUCT_MEMBER;         /* RFC 2132 Requested IP Address */
};

struct pktString
{
  PKT_BASE_MEMBERS;
  char name[];
};

struct pktHostName
{
  PKT_BASE_MEMBERS;     /* Option (12) */
  char name[];          /* RFC 2132 Host Name Option */
};

struct pktParameterRequestList
{
  PKT_BASE_MEMBERS;     /* Option (55) */
  char list[];          /* RFC 2132 Parameter Request List */
};

struct pktAddress
{
  PKT_BASE_MEMBERS;
  char addr[];
};

struct pktServerIdentifier
{
  PKT_BASE_MEMBERS;             /* Option (54) */
  PKT_IP_STRUCT_MEMBER;         /* RFC 2132 Server Identifier */
};

struct pktIpAddressLeaseTime
{
  PKT_BASE_MEMBERS;        /* Option (51) */

  char time[4];            /* RFC 2132 IP Address Lease Time Option */
};

struct pktSubnetMask
{
  PKT_BASE_MEMBERS;         /* Option (1) */
  char subnet[];            /* RFC 2132 Subnet Mask */
};

struct pktRouter
{
  PKT_BASE_MEMBERS;         /* Option (3) */
  char router[];            /* RFC 2132 Router Option */
};

struct pktDomainName
{
  PKT_BASE_MEMBERS;         /* Option (15) */
  char domain[];            /* RFC 2132 Domain Name */
};

struct pktMessage
{
  PKT_BASE_MEMBERS;         /* Option (56) */
  char msg[];               /* RFC 2132 Message */
};

struct pktEnd
{
  u_int8_t option;          /* RFC 2132 End Option */
};

/* complete dhcp option structure */
struct pktDhcpOptions
{
  char cookie[4];
  char opts[0];           /* RFC 2132 */
};

typedef struct pktDhcpPacket pktDhcpPacket_t;

typedef struct pktDhcpOptions pktDhcpOptions_t;

typedef struct pktMessageType pktMessageType_t;

typedef struct pktRequestedIpAddress pktRequestedIpAddress_t;

typedef struct pktString pktString_t;

typedef struct pktHostName pktHostName_t;

typedef struct pktParameterRequestList pktParameterRequestList_t;

typedef struct pktAddress pktAddress_t;

typedef struct pktServerIdentifier pktServerIdentifier_t;

typedef struct pktIpAddressLeaseTime pktIpAddressLeaseTime_t;

typedef struct pktSubnetMask pktSubnetMask_t;

typedef struct pktRouter pktRouter_t;

typedef struct pktDomainName pktDomainName_t;

typedef struct pktMessage pktMessage_t;

typedef struct pktEnd pktEnd_t;

#endif
