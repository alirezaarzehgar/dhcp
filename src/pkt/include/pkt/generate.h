#if !defined(PKT_GENERATE_H)
#define PKT_GENERATE_H

#include "pkt/analyze.h"

int pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer);

int pktGenAck (pktDhcpPacket_t *request, pktDhcpPacket_t *ack);

int
pktGenNak (void *unused /* TODO any parameter sets on future */,
           pktDhcpPacket_t *nak);

void pktGenOptInit();

void pktGenOptEnd (pktDhcpOptions_t *opt);

void pktGenOptMagicCookie (pktDhcpOptions_t *opt, char *cookie);

void pktGenOptIpAddrLeaseTime (pktDhcpOptions_t *opt, uint64_t time);

void pktGenOptDhcpMsgType (pktDhcpOptions_t *opt, int type);

void pktGenOptDhcpServerIdentofier (pktDhcpOptions_t *opt, char *server);

void pktGenOptSubnetMask (pktDhcpOptions_t *opt, char *netmask);

void pktGenOptRouter (pktDhcpOptions_t *opt, char *routerAddr);

void pktGenOptDomainName (pktDhcpOptions_t *opt, char *domainName);

void pktGenFieldClientMacAddress (pktDhcpPacket_t *pkt, char *chaddr);

#endif
