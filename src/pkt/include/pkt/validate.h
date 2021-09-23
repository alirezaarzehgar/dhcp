
#if !defined(VALIDATE_H)
#define VALIDATE_H

#include "dhcp.h"
#include <stdbool.h>
#include "analyze.h"
#include <ctype.h>

#define PKT_MAX_IP_SEGMENT_LEN                  255
#define PKT_DEFAULT_ADDRESS_LEN                 4

bool pkt_is_msg_type_valid (enum dhcpMessageTypes type);

bool pkt_is_msg_type_option_valid (pktMessageType_t *opt);

bool pkt_is_requested_ip_addr_option_valid (pktRequestedIpAddress_t *opt);

bool pkt_is_host_name_option_valid (pktString_t *opt);

bool pkt_is_parameter_list_valid (pktParameterRequestList_t *opt);

bool pkt_is_valid_server_identifier (pktServerIdentifier_t *opt);

bool pkt_is_valid_str_ip (char *ip);

bool pkt_is_ip_address_lease_time_option_valid (pktIpAddressLeaseTime_t *opt);

bool pkt_is_valid_subnet_mask (pktSubnetMask_t *opt);

bool pkt_is_address_valid (pktAddress_t *opt, int option,  int max);

bool pkt_is_valid_router (pktRouter_t *opt);

bool pkt_is_valid_string (pktString_t *opt, int option);

bool pkt_is_domain_name_option_valid (pktString_t *opt);

bool pkt_is_message_valid (pktString_t *opt);

#endif // VALIDATE_H
