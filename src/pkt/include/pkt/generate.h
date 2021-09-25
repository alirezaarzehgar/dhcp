#if !defined(PKT_GENERATE_H)
#define PKT_GENERATE_H

#include "pkt/analyze.h"

int pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer);

int pktGenAck (pktDhcpPacket_t *request, pktDhcpPacket_t *ack);

#endif
