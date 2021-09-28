#include <CUnit/TestDB.h>

#include "pkt/analyze_test.h"
#include "pkt/generation_test.h"
#include "pkt/validate_test.h"

#if !defined(TEST_PKT_ARRAY_H)
#define TEST_PKT_ARRAY_H

CU_TestInfo pkt_tests[] =
{
  /* Validation tests */
  {"validation function pktIsMsgTypeValidTest", pktIsMsgTypeValidTest},
  {"validation function pktIsMsgTypeOptionValidTest", pktIsMsgTypeOptionValidTest},
  {"validation function pktIsRequestedIpAddrOptionValidTest", pktIsRequestedIpAddrOptionValidTest},
  {"validation function pktIsHostNameOptionValidTest", pktIsHostNameOptionValidTest},
  {"validation function pktIsParameterListValidTest", pktIsParameterListValidTest},
  {"validation function pktIsValidServerIdentifierTest", pktIsValidServerIdentifierTest},
  {"validation function pktIsIpAddressLeaseTimeOptionValidTest", pktIsIpAddressLeaseTimeOptionValidTest},
  {"validation function pktLeaseTimeHex2longTest", pktLeaseTimeHex2longTest},
  {"validation function pktLeaseTimeLong2hexTest", pktLeaseTimeLong2hexTest},
  {"validation function pktIsValidSubnetMaskTest", pktIsValidSubnetMaskTest},
  {"validation function pktIsAddressValidTest", pktIsAddressValidTest},
  {"validation function pktIsValidRouterTest", pktIsValidRouterTest},
  {"validation function pktIsValidStringTest", pktIsValidStringTest},
  {"validation function pktIsDomainNameOptionValidTest", pktIsDomainNameOptionValidTest},
  {"validation function pktIsMessageValidTest", pktIsMessageValidTest},
  {"validation function pktIsDiscoveryPktValidForOfferTest", pktIsDiscoveryPktValidForOfferTest},
  {"validation function pktIsRequestPktValidForAckTest", pktIsRequestPktValidForAckTest},
  {"validation function pktIsPktTypeBootReqTest", pktIsPktTypeBootReqTest},
  {"validation function pktIsPktTypeBootRepTest", pktIsPktTypeBootRepTest},
  {"validation function pktHaveTransactionIdTest", pktHaveTransactionIdTest},
  {"validation function pktIsValidMacAddressTest", pktIsValidMacAddressTest},
  {"validation function pktHaveMagicCookieTest", pktHaveMagicCookieTest},
  {"validation function pktHaveHostNameTest", pktHaveHostNameTest},
  {"validation function pktValidateWithListOfConditionsTest", pktValidateWithListOfConditionsTest},
  {"validation function pktHaveParameterRequestListOptionTest", pktHaveParameterRequestListOptionTest},
  /* Analyze Tests */
  {"get magic cookie", pktGetMagicCookieTest},
  {"get message type", pktGetDhcpMessageTypeTest},
  {"get requested ip address", pktGetRequestedIpAddressTest},
  {"get host name", pktGetHostNameTest},
  {"get parameter list", pktGetParameterListTest},
  {"get server identifier", pktGetServerIdentifierTest},
  {"convert ip string to hex", pktIpStr2hexTest},
  {"convert ip hex to string", pktIpHex2strTest},
  {"get ip address lease time", pktGetIpAddressLeaseTimeTest},
  {"offer file test", pktOfferFileTest},
  {"pkt get subnet mask", pktGetSubnetMaskTest},
  {"pkt get address", pktGetAddressTest},
  {"pkt get router", pktgetRouterTest},
  {"pkt get domain name", pktGetDomainNameTest},
  {"pkt get error message", pktGetMessageTest},
  {"convert address string to hex", pktAddrStr2hexTest},
  {"convert address hex to string", pktAddrHex2strTest},
  {"convert mac address string to hex", pktMacStr2hexTest},
  {"convert mac address hex to string", pktMacHex2strTest},
  /* Generation Tests */
  {"endpoint for packet generation", packetGenMainTest},
  {"generate Offer packet", pktGenOfferTest},
  {"generate Ack packet", pktGenAckTest},
  CU_TEST_INFO_NULL,
};

#endif
