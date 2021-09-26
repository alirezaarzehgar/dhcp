#if !defined(PKT_GENERATE_H)
#define PKT_GENERATE_H

#include "pkt/analyze.h"

typedef void (*pktGenCallbackFunc_t) (void *, void *);

struct pktGenCallback
{
  pktGenCallbackFunc_t func;

  void *param;
};

typedef struct pktGenCallback pktGenCallback_t;

int pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer,
                 pktGenCallback_t *blocks, size_t blocksLen, pktGenCallback_t *options,
                 size_t optionsLen);

int pktGenAck (pktDhcpPacket_t *request, pktDhcpPacket_t *ack);

int
pktGenNak (void *unused /* TODO any parameter sets on future */,
           pktDhcpPacket_t *nak);

void pktGenOptInit();

void pktGenOptEnd (pktDhcpOptions_t *opt);

void pktGenOptMagicCookie (pktDhcpOptions_t *opt, char *cookie);

void pktGenOptIpAddrLeaseTime (pktDhcpOptions_t *opt, uint32_t time);

void pktGenOptDhcpMsgType (pktDhcpOptions_t *opt, int type);

void pktGenOptDhcpServerIdentofier (pktDhcpOptions_t *opt, char *server);

void pktGenOptSubnetMask (pktDhcpOptions_t *opt, char *netmask);

void pktGenOptRouter (pktDhcpOptions_t *opt, char *routerAddr);

void pktGenOptDomainName (pktDhcpOptions_t *opt, char *domainName);

void pktGenFieldClientMacAddress (pktDhcpPacket_t *pkt, char *chaddr);

void pktGenFieldOperationCode (pktDhcpPacket_t *pkt, int op);

void pktGenFieldHardwareType (pktDhcpPacket_t *pkt, int htype);

void pktGenFieldTransactionId (pktDhcpPacket_t *pkt, int xid);

void pktGenFieldYourIpAddress (pktDhcpPacket_t *pkt, char *yip);

void pktGenFieldHardwareLen (pktDhcpPacket_t *pkt, int len);

#endif
