
#if !defined(VALIDATE_H)
#define VALIDATE_H

#include "dhcp.h"
#include <stdbool.h>
#include "analyze.h"
#include <ctype.h>

#define PKT_MAX_IP_SEGMENT_LEN                  255
#define PKT_DEFAULT_ADDRESS_LEN                 4
#define PKT_HLEN                                6
#define PKT_TRANSACTION_ID_LEN                  4
#define PKT_HEX_NULL                            0x0

typedef bool (*pktOptValidator_t) (pktDhcpPacket_t *);

bool pktIsMsgTypeValid (enum dhcpMessageTypes type);

bool pktIsMsgTypeOptionValid (pktMessageType_t *opt);

bool pktIsRequestedIpAddrOptionValid (pktRequestedIpAddress_t *opt);

bool pktIsHostNameOptionValid (pktString_t *opt);

bool pktIsParameterListValid (pktParameterRequestList_t *opt);

bool pktIsValidServerIdentifier (pktServerIdentifier_t *opt);

bool pkt_is_valid_str_ip (char *ip);

bool pktIsIpAddressLeaseTimeOptionValid (pktIpAddressLeaseTime_t *opt);

bool pktIsValidSubnetMask (pktSubnetMask_t *opt);

bool pktIsAddressValid (pktAddress_t *opt, int option,  int max);

bool pktIsValidRouter (pktRouter_t *opt);

bool pktIsValidString (pktString_t *opt, int option);

bool pktIsDomainNameOptionValid (pktString_t *opt);

bool pktIsMessageValid (pktString_t *opt);

bool pktIsPktTypeBootReq (pktDhcpPacket_t *pkt);

bool pktIsPktTypeBootRep (pktDhcpPacket_t *pkt);

bool pktIsDiscoveryPktValidForOffer (pktDhcpPacket_t *pkt);

bool pktIsRequestPktValidForAck (pktDhcpPacket_t *pkt);

bool pktHaveTransactionId (pktDhcpPacket_t *pkt);

bool pktIsValidMacAddress (pktDhcpPacket_t *pkt);

bool pktHaveMagicCookie (pktDhcpPacket_t *pkt);

bool pktIsMsgTypeDiscovery (pktDhcpPacket_t *pkt);

bool pktIsMsgTypeRequest (pktDhcpPacket_t *pkt);

bool pktHaveHostNameOption (pktDhcpPacket_t *pkt);

bool pktValidateWithListOfConditions (pktOptValidator_t *conditions,
                                      pktDhcpPacket_t *pkt, size_t len);

bool pktHaveParameterRequestListOption (pktDhcpPacket_t *pkt);

#endif
