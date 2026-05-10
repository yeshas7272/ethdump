#include "unity.h"
#include "parser.h"
#include "ringbuff.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> /* TH_SYN, TH_ACK, ... */

void setUp(void) {}
void tearDown(void) {}

/* =========================================================================
 * Helper
 * ========================================================================= */

static pkt_slot_t make_slot(const uint8_t *data, uint32_t len)
{
    pkt_slot_t slot;
    memset(&slot, 0, sizeof(slot));
    slot.caplen  = len;
    slot.origlen = len;
    memcpy(slot.data, data, len);
    return slot;
}

/* =========================================================================
 * Raw packet fixtures
 *
 * All frames use:
 *   dst MAC  aa:bb:cc:dd:ee:ff
 *   src MAC  11:22:33:44:55:66
 *   src IP   192.168.1.1
 *   dst IP   192.168.1.2
 *   TTL      64
 * ========================================================================= */

/* --- Ethernet / IPv4 / TCP (SYN) — 54 bytes ----------------------------- */
/* clang-format off */
static const uint8_t pkt_ipv4_tcp[] = {
    /* Ethernet */
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,    /* dst MAC */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,    /* src MAC */
    0x08, 0x00,                             /* EtherType: IPv4 */
    /* IPv4  (IHL=5, total_len=40) */
    0x45, 0x00, 0x00, 0x28,                 /* ver/IHL/DSCP/len */
    0x00, 0x01, 0x40, 0x00,                 /* id/flags/frag */
    0x40, 0x06, 0x00, 0x00,                 /* TTL=64 / proto=TCP / cksum */
    0xc0, 0xa8, 0x01, 0x01,                 /* src: 192.168.1.1 */
    0xc0, 0xa8, 0x01, 0x02,                 /* dst: 192.168.1.2 */
    /* TCP  (data_off=5) */
    0x00, 0x50, 0x04, 0x00,                 /* sport=80  dport=1024 */
    0x00, 0x00, 0x00, 0x01,                 /* seq=1 */
    0x00, 0x00, 0x00, 0x00,                 /* ack=0 */
    0x50, 0x02,                             /* data_off=5 / flags=SYN */
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00,    /* window / cksum / urg */
};

/* --- Ethernet / IPv4 / UDP — 42 bytes ------------------------------------ */
static const uint8_t pkt_ipv4_udp[] = {
    /* Ethernet */
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    /* IPv4  (IHL=5, total_len=28) */
    0x45, 0x00, 0x00, 0x1c,
    0x00, 0x02, 0x40, 0x00,
    0x40, 0x11, 0x00, 0x00,                 /* proto=UDP */
    0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02,
    /* UDP */
    0x00, 0x35, 0x04, 0x00,                 /* sport=53  dport=1024 */
    0x00, 0x08, 0x00, 0x00,                 /* len=8 / cksum */
};

/* --- Ethernet / IPv4 / ICMP Echo Request — 42 bytes ---------------------- */
static const uint8_t pkt_ipv4_icmp[] = {
    /* Ethernet */
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    /* IPv4  (IHL=5, total_len=28) */
    0x45, 0x00, 0x00, 0x1c,
    0x00, 0x03, 0x40, 0x00,
    0x40, 0x01, 0x00, 0x00,                 /* proto=ICMP */
    0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02,
    /* ICMP */
    0x08, 0x00,                             /* type=8 (echo req) / code=0 */
    0x00, 0x00,                             /* cksum */
    0x00, 0x01, 0x00, 0x01,                 /* id / seq */
};

/* --- Ethernet / IPv6 / TCP (SYN) — 74 bytes ------------------------------ */
static const uint8_t pkt_ipv6_tcp[] = {
    /* Ethernet */
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x86, 0xdd,                             /* EtherType: IPv6 */
    /* IPv6  (payload_len=20, next=TCP, hop_limit=64) */
    0x60, 0x00, 0x00, 0x00,                 /* ver=6 / tc / flow */
    0x00, 0x14, 0x06, 0x40,                 /* payload_len=20 / next=TCP / hlim=64 */
    0x20, 0x01, 0x0d, 0xb8,                 /* src: 2001:db8::1 */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x20, 0x01, 0x0d, 0xb8,                 /* dst: 2001:db8::2 */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
    /* TCP  (data_off=5, flags=SYN) */
    0x00, 0x50, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
};

/* --- Ethernet / ARP Request — 42 bytes ----------------------------------- */
static const uint8_t pkt_arp[] = {
    /* Ethernet */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,    /* dst: broadcast */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x06,                             /* EtherType: ARP */
    /* ARP */
    0x00, 0x01,                             /* htype=Ethernet */
    0x08, 0x00,                             /* ptype=IPv4 */
    0x06, 0x04,                             /* hlen=6 / plen=4 */
    0x00, 0x01,                             /* opcode=request */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,    /* sender MAC */
    0xc0, 0xa8, 0x01, 0x01,                 /* sender IP: 192.168.1.1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* target MAC: unknown */
    0xc0, 0xa8, 0x01, 0x02,                 /* target IP: 192.168.1.2 */
};

/* --- Ethernet (802.1Q VLAN) / IPv4 / TCP — 58 bytes --------------------- */
/* VLAN: PCP=1, VID=100  →  TCI = (1<<13)|100 = 0x2064 */
static const uint8_t pkt_vlan_ipv4_tcp[] = {
    /* Ethernet */
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x81, 0x00,                             /* EtherType: 802.1Q */
    /* VLAN tag */
    0x20, 0x64,                             /* TCI: PCP=1, VID=100 */
    0x08, 0x00,                             /* inner EtherType: IPv4 */
    /* IPv4 + TCP (identical to pkt_ipv4_tcp) */
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x01, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02,
    0x00, 0x50, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
};

/* --- Ethernet (802.1ad QinQ) / IPv4 / TCP — 62 bytes -------------------- */
/* Outer VLAN: PCP=2, VID=200  →  TCI = (2<<13)|200 = 0x40C8             */
/* Inner VLAN: PCP=1, VID=100  →  TCI = (1<<13)|100 = 0x2064             */
static const uint8_t pkt_qinq_ipv4_tcp[] = {
    /* Ethernet */
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x88, 0xa8,                             /* EtherType: 802.1ad */
    /* Outer VLAN tag */
    0x40, 0xc8,                             /* TCI: PCP=2, VID=200 */
    0x81, 0x00,                             /* inner EtherType: 802.1Q */
    /* Inner VLAN tag */
    0x20, 0x64,                             /* TCI: PCP=1, VID=100 */
    0x08, 0x00,                             /* inner EtherType: IPv4 */
    /* IPv4 + TCP */
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x01, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xc0, 0xa8, 0x01, 0x01,
    0xc0, 0xa8, 0x01, 0x02,
    0x00, 0x50, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
};
/* clang-format on */

/* =========================================================================
 * Tests — IPv4
 * ========================================================================= */

void test_parse_ipv4_tcp(void)
{
    pkt_slot_t   slot = make_slot(pkt_ipv4_tcp, sizeof(pkt_ipv4_tcp));
    parsed_pkt_t pkt;

    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));

    /* L2 */
    uint8_t exp_dst[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t exp_src[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    TEST_ASSERT_EQUAL_MEMORY(exp_dst, pkt.dst_mac, 6);
    TEST_ASSERT_EQUAL_MEMORY(exp_src, pkt.src_mac, 6);
    TEST_ASSERT_EQUAL_UINT16(0, pkt.vlan_id);

    /* L3 */
    TEST_ASSERT_EQUAL_INT(L3_PROTO_IPV4, pkt.l3_proto);
    TEST_ASSERT_EQUAL_UINT8(4, pkt.ip_version);
    TEST_ASSERT_EQUAL_UINT8(64, pkt.ttl);

    uint32_t exp_src_ip, exp_dst_ip;
    inet_pton(AF_INET, "192.168.1.1", &exp_src_ip);
    inet_pton(AF_INET, "192.168.1.2", &exp_dst_ip);
    TEST_ASSERT_EQUAL_UINT32(exp_src_ip, pkt.src_ip.v4.s_addr);
    TEST_ASSERT_EQUAL_UINT32(exp_dst_ip, pkt.dst_ip.v4.s_addr);

    /* L4 */
    TEST_ASSERT_EQUAL_INT(L4_PROTO_TCP, pkt.l4_proto);
    TEST_ASSERT_EQUAL_UINT16(80, pkt.src_port);
    TEST_ASSERT_EQUAL_UINT16(1024, pkt.dst_port);
    TEST_ASSERT_BITS(TH_SYN, TH_SYN, pkt.tcp_flags);
    TEST_ASSERT_BITS(TH_ACK, 0, pkt.tcp_flags);
}

void test_parse_ipv4_udp(void)
{
    pkt_slot_t   slot = make_slot(pkt_ipv4_udp, sizeof(pkt_ipv4_udp));
    parsed_pkt_t pkt;

    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));

    TEST_ASSERT_EQUAL_INT(L3_PROTO_IPV4, pkt.l3_proto);
    TEST_ASSERT_EQUAL_INT(L4_PROTO_UDP, pkt.l4_proto);
    TEST_ASSERT_EQUAL_UINT16(53, pkt.src_port);
    TEST_ASSERT_EQUAL_UINT16(1024, pkt.dst_port);
}

void test_parse_ipv4_icmp(void)
{
    pkt_slot_t   slot = make_slot(pkt_ipv4_icmp, sizeof(pkt_ipv4_icmp));
    parsed_pkt_t pkt;

    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));

    TEST_ASSERT_EQUAL_INT(L3_PROTO_IPV4, pkt.l3_proto);
    TEST_ASSERT_EQUAL_INT(L4_PROTO_ICMP, pkt.l4_proto);
    TEST_ASSERT_EQUAL_UINT8(8, pkt.icmp_type); /* echo request */
    TEST_ASSERT_EQUAL_UINT8(0, pkt.icmp_code);
}

/* =========================================================================
 * Tests — IPv6
 * ========================================================================= */

void test_parse_ipv6_tcp(void)
{
    pkt_slot_t   slot = make_slot(pkt_ipv6_tcp, sizeof(pkt_ipv6_tcp));
    parsed_pkt_t pkt;

    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));

    TEST_ASSERT_EQUAL_INT(L3_PROTO_IPV6, pkt.l3_proto);
    TEST_ASSERT_EQUAL_UINT8(6, pkt.ip_version);
    TEST_ASSERT_EQUAL_UINT8(64, pkt.ttl); /* hop limit */

    struct in6_addr exp_src, exp_dst;
    inet_pton(AF_INET6, "2001:db8::1", &exp_src);
    inet_pton(AF_INET6, "2001:db8::2", &exp_dst);
    TEST_ASSERT_EQUAL_MEMORY(&exp_src, &pkt.src_ip.v6, sizeof(exp_src));
    TEST_ASSERT_EQUAL_MEMORY(&exp_dst, &pkt.dst_ip.v6, sizeof(exp_dst));

    TEST_ASSERT_EQUAL_INT(L4_PROTO_TCP, pkt.l4_proto);
    TEST_ASSERT_EQUAL_UINT16(80, pkt.src_port);
    TEST_ASSERT_EQUAL_UINT16(1024, pkt.dst_port);
}

/* =========================================================================
 * Tests — ARP
 * ========================================================================= */

void test_parse_arp_request(void)
{
    pkt_slot_t   slot = make_slot(pkt_arp, sizeof(pkt_arp));
    parsed_pkt_t pkt;

    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));

    TEST_ASSERT_EQUAL_INT(L3_PROTO_ARP, pkt.l3_proto);
    TEST_ASSERT_EQUAL_UINT16(1, pkt.arp_opcode); /* request */

    uint8_t exp_sender_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    TEST_ASSERT_EQUAL_MEMORY(exp_sender_mac, pkt.arp_sender_mac, 6);

    uint32_t exp_sender_ip, exp_target_ip;
    inet_pton(AF_INET, "192.168.1.1", &exp_sender_ip);
    inet_pton(AF_INET, "192.168.1.2", &exp_target_ip);
    TEST_ASSERT_EQUAL_UINT32(exp_sender_ip, pkt.arp_sender_ip.s_addr);
    TEST_ASSERT_EQUAL_UINT32(exp_target_ip, pkt.arp_target_ip.s_addr);
}

/* =========================================================================
 * Tests — VLAN / QinQ
 * ========================================================================= */

void test_parse_vlan_ipv4_tcp(void)
{
    pkt_slot_t   slot = make_slot(pkt_vlan_ipv4_tcp, sizeof(pkt_vlan_ipv4_tcp));
    parsed_pkt_t pkt;

    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));

    TEST_ASSERT_EQUAL_UINT16(100, pkt.vlan_id);
    TEST_ASSERT_EQUAL_UINT8(1, pkt.vlan_pcp);
    TEST_ASSERT_EQUAL_UINT16(0, pkt.inner_vlan_id);

    TEST_ASSERT_EQUAL_INT(L3_PROTO_IPV4, pkt.l3_proto);
    TEST_ASSERT_EQUAL_INT(L4_PROTO_TCP, pkt.l4_proto);
    TEST_ASSERT_EQUAL_UINT16(80, pkt.src_port);
}

void test_parse_qinq_ipv4_tcp(void)
{
    pkt_slot_t   slot = make_slot(pkt_qinq_ipv4_tcp, sizeof(pkt_qinq_ipv4_tcp));
    parsed_pkt_t pkt;

    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));

    TEST_ASSERT_EQUAL_UINT16(200, pkt.vlan_id);
    TEST_ASSERT_EQUAL_UINT8(2, pkt.vlan_pcp);
    TEST_ASSERT_EQUAL_UINT16(100, pkt.inner_vlan_id);
    TEST_ASSERT_EQUAL_UINT8(1, pkt.inner_vlan_pcp);

    TEST_ASSERT_EQUAL_INT(L3_PROTO_IPV4, pkt.l3_proto);
    TEST_ASSERT_EQUAL_INT(L4_PROTO_TCP, pkt.l4_proto);
}

/* =========================================================================
 * Tests — truncation / malformed
 * ========================================================================= */

void test_parse_truncated_eth(void)
{
    /* Only 10 bytes — shorter than the 14-byte Ethernet header */
    pkt_slot_t   slot = make_slot(pkt_ipv4_tcp, 10);
    parsed_pkt_t pkt;
    TEST_ASSERT_FALSE(parse_packet(&slot, &pkt));
}

void test_parse_truncated_ipv4(void)
{
    /* Full Ethernet header, but IPv4 header is cut short */
    pkt_slot_t   slot = make_slot(pkt_ipv4_tcp, 14 + 10);
    parsed_pkt_t pkt;
    TEST_ASSERT_FALSE(parse_packet(&slot, &pkt));
}

void test_parse_truncated_tcp(void)
{
    /* Full Ethernet + IPv4, but TCP header is cut short */
    pkt_slot_t   slot = make_slot(pkt_ipv4_tcp, 14 + 20 + 10);
    parsed_pkt_t pkt;
    TEST_ASSERT_FALSE(parse_packet(&slot, &pkt));
}

void test_parse_unknown_ethertype(void)
{
    /* Replace EtherType with 0x9999 (unknown) */
    uint8_t buf[sizeof(pkt_ipv4_tcp)];
    memcpy(buf, pkt_ipv4_tcp, sizeof(buf));
    buf[12] = 0x99;
    buf[13] = 0x99;

    pkt_slot_t   slot = make_slot(buf, sizeof(buf));
    parsed_pkt_t pkt;

    /* Unknown L3 is not an error — parser returns true */
    TEST_ASSERT_TRUE(parse_packet(&slot, &pkt));
    TEST_ASSERT_EQUAL_INT(L3_PROTO_UNKNOWN, pkt.l3_proto);
    TEST_ASSERT_EQUAL_INT(L4_PROTO_UNKNOWN, pkt.l4_proto);
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_parse_ipv4_tcp);
    RUN_TEST(test_parse_ipv4_udp);
    RUN_TEST(test_parse_ipv4_icmp);

    RUN_TEST(test_parse_ipv6_tcp);

    RUN_TEST(test_parse_arp_request);

    RUN_TEST(test_parse_vlan_ipv4_tcp);
    RUN_TEST(test_parse_qinq_ipv4_tcp);

    RUN_TEST(test_parse_truncated_eth);
    RUN_TEST(test_parse_truncated_ipv4);
    RUN_TEST(test_parse_truncated_tcp);
    RUN_TEST(test_parse_unknown_ethertype);

    return UNITY_END();
}
