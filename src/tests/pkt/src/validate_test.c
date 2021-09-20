/**
 * @file validate.c
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2021-09-20
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/validate_test.h"
#include "pkt/validate.h"

void
pkt_is_msg_type_valid_test()
{
  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCP_MSG_TYPE_DISCOVER));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCP_MSG_TYPE_ACK));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCP_MSG_TYPE_NAK));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCP_MSG_TYPE_OFFER));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCP_MSG_TYPE_RELEASE));

  CU_ASSERT_TRUE (pkt_is_msg_type_valid (DHCP_MSG_TYPE_REQUEST));

  CU_ASSERT_FALSE (pkt_is_msg_type_valid (DHCP_MSG_TYPE_UNKNOW));

  CU_ASSERT_FALSE (pkt_is_msg_type_valid (423));
}

void
pkt_is_msg_type_option_valid_test()
{
  pktMessageType_t opt = {.len = 1, .type = DHCP_MSG_TYPE_DISCOVER, .option = OPTION_DHCP_MSG_TYPE};

  CU_ASSERT_TRUE (pkt_is_msg_type_option_valid (&opt));

  opt.len = 12;

  CU_ASSERT_FALSE (pkt_is_msg_type_option_valid (&opt));

  opt.len = 1;

  opt.type = DHCP_MSG_TYPE_UNKNOW;

  CU_ASSERT_FALSE (pkt_is_msg_type_option_valid (&opt));

  opt.type = DHCP_MSG_TYPE_DISCOVER;

  opt.option = OPTION_COOKIE_SERVER;

  CU_ASSERT_FALSE (pkt_is_msg_type_option_valid (&opt));

}

void
pkt_is_requested_ip_addr_option_valid_test()
{
  pktRequestedIpAddress_t opt = {.len = 0, .option = OPTION_REQUESTED_IP_ADDR};

  CU_ASSERT_TRUE (pkt_is_requested_ip_addr_option_valid (&opt));
}