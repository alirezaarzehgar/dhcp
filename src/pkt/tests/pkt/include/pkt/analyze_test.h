#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/fcntl.h>

#include "pkt/core.h"

#include <CUnit/Basic.h>

#if !defined(TESTS_PKT_ANALYZE_TESTS_H)
#define TESTS_PKT_ANALYZE_TESTS_H

#define PKT_FAILED_OPEN_FILE(fd, path)   if (fd == -1)     \
    {   \
      fprintf (stdout, "error %s : %s", path, strerror (errno));    \
      return CUE_TEST_INACTIVE; \
    }   \

typedef void (*pktCustomTest_t) (pktDhcpPacket_t *pkt, int index);

void pktTestFunctionOnAllPackets (pktCustomTest_t func);

void pktTestFunctionWithEmptyPkt (pktValidator_t func);

int initSuitePkt();

int cleanupSuitePkt();

void pktGetMagicCookieTest();

void pktGetRequestedIpAddressTest();

void pktGetDhcpMessageTypeTest();

void pktGetHostNameTest();

void pktGetParameterListTest();

void pktGetServerIdentifierTest();

void pktIpHex2strTest();

void pktIpStr2hexTest();

void pktGetIpAddressLeaseTimeTest();

void pktOfferFileTest();

void pktLeaseTimeHex2longTest();

void pktLeaseTimeLong2hexTest();

void pktGetSubnetMaskTest();

void pktGetAddressTest();

void pktgetRouterTest();

void pktGetDomainNameTest();

void pktGetStringTest();

void pktGetMessageTest();

void pktAddrStr2hexTest();

void pktAddrHex2strTest();

void pktMacStr2hexTest();

void pktMacHex2strTest();

#endif
