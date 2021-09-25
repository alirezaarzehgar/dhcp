#if !defined(PKT_GENERATE_H)
#define PKT_GENERATE_H

#include "pkt/analyze.h"

int pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer);

int pktGenAck (pktDhcpPacket_t *request, pktDhcpPacket_t *ack);

int
pktGenNak (void *unused /* TODO any parameter sets on future */,
           pktDhcpPacket_t *nak);

#endif
