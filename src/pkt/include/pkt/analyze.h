#include "dhcp.h"

#if !defined(PKT_ANALYZE_H)
#define PKT_ANALYZE_H

#define DHCP_MAGIC_COOKIE_SIZE               4

char *get_magic_cookie (dhcp_packet_t *pkt);

void print_magic_cookie (dhcp_packet_t *pkt);

struct in_addr get_requested_ip_address (dhcp_packet_t *pkt);

#endif // PKT_ANALYZE_H
