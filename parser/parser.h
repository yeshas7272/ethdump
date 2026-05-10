#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h> /* struct in_addr, struct in6_addr */
#include <sys/time.h>

#include "ringbuff.h"

/* Protocol enums */

typedef enum
{
    L3_PROTO_UNKNOWN = 0,
    L3_PROTO_IPV4,
    L3_PROTO_IPV6,
    L3_PROTO_ARP,
    L3_PROTO_VLAN,
    L3_PROTO_QINQ,
    L3_PROTO_COUNT
} l3_proto_t;

typedef enum
{
    L4_PROTO_UNKNOWN = 0,
    L4_PROTO_TCP,
    L4_PROTO_UDP,
    L4_PROTO_ICMP,
    L4_PROTO_ICMPV6,
    L4_PROTO_COUNT
} l4_proto_t;

/**
 * Parsed packet
 *
 * Filled in by parse_packet(). Fields are only valid if the corresponding
 * proto field is not UNKNOWN.
 */

typedef struct
{
    struct timeval ts;
    uint32_t       caplen;
    uint32_t       origlen;

    /* L2 */
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint16_t vlan_id;        /* outer VLAN id (VID), 0 if not present  */
    uint8_t  vlan_pcp;       /* outer PCP (0-7), 0 if not present      */
    uint16_t inner_vlan_id;  /* inner VLAN id (QinQ), 0 if not present */
    uint8_t  inner_vlan_pcp; /* inner PCP (0-7), 0 if not present      */

    /* L3 */
    l3_proto_t     l3_proto;
    uint16_t       arp_opcode;
    struct in_addr arp_sender_ip;
    struct in_addr arp_target_ip;
    uint8_t        arp_sender_mac[6];
    uint8_t        arp_target_mac[6];

    uint8_t ip_version; /* 4 or 6                                 */
    uint8_t ttl;
    union
    {
        struct in_addr  v4;
        struct in6_addr v6;
    } src_ip, dst_ip;

    /* L4 */
    l4_proto_t l4_proto;
    uint16_t   src_port;
    uint16_t   dst_port;
    uint8_t    tcp_flags; /* only valid when l4_proto == L4_PROTO_TCP          */
    uint8_t    icmp_type; /* only valid when l4_proto == L4_PROTO_ICMP/ICMPV6 */
    uint8_t    icmp_code;
} parsed_pkt_t;

/* Parser APIs */

bool parse_packet(const pkt_slot_t *slot, parsed_pkt_t *out);
void print_packet(const parsed_pkt_t *pkt);

#endif /* PARSER_H */