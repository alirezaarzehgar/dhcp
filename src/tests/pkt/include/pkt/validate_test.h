#if !defined(TEST_VALIDATE_H)
#define TEST_VALIDATE_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/fcntl.h>

#include <CUnit/Basic.h>

void pktIsMsgTypeValidTest();

void pktIsMsgTypeOptionValidTest();

void pktIsRequestedIpAddrOptionValidTest();

void pktIsHostNameOptionValidTest();

void pktIsParameterListValidTest();

void pktIsValidServerIdentifierTest();

void pktIsIpAddressLeaseTimeOptionValidTest();

void pktIsValidSubnetMaskTest();

void pktIsAddressValidTest();

void pktIsValidRouterTest();

void pktIsValidStringTest();

void pktIsDomainNameOptionValidTest();

void pktIsMessageValidTest();

void pktIsDiscoveryPktValidForOfferTest();

void pktIsRequestPktValidForAckTest();

void pktIsPktTypeBootReqTest();

void pktIsPktTypeBootRepTest();

void pktHaveTransactionIdTest();

void pktIsValidMacAddressTest();

void pktHaveMagicCookieTest();

void pktIsMsgTypeDiscoveryTest();

void pktIsMsgTypeRequestTest();

void pktHaveHostNameTest();

void pktValidateWithListOfConditionsTest();

void pktHaveParameterRequestListOptionTest();

#endif
