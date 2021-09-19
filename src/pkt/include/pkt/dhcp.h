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

// #define DHCP_STRUCT_OPTION()

struct dhcp_packet
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

struct dhcp_options
{
  char cookie[4];

  struct
  {
    char option;
    char len;
    char type;
  } messageType;

  struct
  {
    char option;
    char len;
    char ip[];
  } requestedIpAddress;

  struct
  {
    char option;
    char len;
    char name[];
  } hostName;

  struct
  {
    char option;
    char len;
    char list[];
  } parameterRequestList;
};

typedef struct dhcp_packet dhcp_packet_t;

typedef struct dhcp_options dhcp_options_t;

#endif // PKT_DHCP_H
