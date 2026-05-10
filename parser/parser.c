#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "parser.h"
#include "log.h"

/* =========================================================================
 * Ethernet constants
 * ========================================================================= */

#define ETH_ALEN 6
#define ETH_HLEN 14     /* dst(6) + src(6) + ethertype(2)           */
#define ETH_VLAN_HLEN 4 /* tci(2) + ethertype(2)                    */

#define ETHERTYPE_IPV4 0x0800u
#define ETHERTYPE_ARP 0x0806u
#define ETHERTYPE_VLAN 0x8100u
#define ETHERTYPE_QINQ 0x88A8u
#define ETHERTYPE_IPV6 0x86DDu

/* =========================================================================
 * VLAN (802.1Q) TCI field layout
 * ========================================================================= */

#define VLAN_PCP_SHIFT 13u   /* PCP occupies bits 15:13               */
#define VLAN_PCP_MASK 0x07u  /* 3-bit PCP field                       */
#define VLAN_ID_MASK 0x0FFFu /* 12-bit VID field                      */

/* =========================================================================
 * ARP constants (RFC 826 — IPv4 over Ethernet)
 * ========================================================================= */

#define ARP_HLEN 28u         /* total header length                       */
#define ARP_OFFSET_OPCODE 6u /* opcode field                              */
#define ARP_OFFSET_SHA 8u    /* sender hardware address                   */
#define ARP_OFFSET_SPA 14u   /* sender protocol address                   */
#define ARP_OFFSET_THA 18u   /* target hardware address                   */
#define ARP_OFFSET_TPA 24u   /* target protocol address                   */

#define ARP_OP_REQUEST 1u /* ARP request                               */
#define ARP_OP_REPLY 2u   /* ARP reply                                 */

/* =========================================================================
 * Dispatch tables
 * ========================================================================= */

typedef bool (*parse_fn)(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);

/* parser functions for dispatch tables */
static bool parse_ipv4(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);
static bool parse_ipv6(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);
static bool parse_arp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);
static bool parse_tcp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);
static bool parse_udp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);
static bool parse_icmp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);
static bool parse_icmpv6(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset);

/* clang-format off */
static const parse_fn l3_table[L3_PROTO_COUNT] = {
	[L3_PROTO_UNKNOWN]      = NULL,
	[L3_PROTO_IPV4]         = parse_ipv4,
	[L3_PROTO_IPV6]         = parse_ipv6,
	[L3_PROTO_ARP]          = parse_arp, 
	[L3_PROTO_VLAN]         = NULL, /* handled inline in parse_eth */
	[L3_PROTO_QINQ]         = NULL, /* handled inline in parse_eth */
};

static const parse_fn l4_table[L4_PROTO_COUNT] = {
	[L4_PROTO_UNKNOWN]      = NULL,
	[L4_PROTO_TCP]          = parse_tcp,
	[L4_PROTO_UDP]          = parse_udp,
	[L4_PROTO_ICMP]         = parse_icmp,
	[L4_PROTO_ICMPV6]       = parse_icmpv6,
};
/* clang-format on */

/* =========================================================================
 * Translation — wire value → enum
 * ========================================================================= */

/**
 * Maps a 16-bit EtherType to an l3_proto_t enum value.
 * ethertype : raw EtherType field from the Ethernet header (host byte order)
 *
 * Returns the matching l3_proto_t, or L3_PROTO_UNKNOWN if unsupported.
 */
static l3_proto_t ethertype_to_l3(uint16_t ethertype)
{
    switch (ethertype)
    {
    case ETHERTYPE_IPV4:
        return L3_PROTO_IPV4;
    case ETHERTYPE_IPV6:
        return L3_PROTO_IPV6;
    case ETHERTYPE_ARP:
        return L3_PROTO_ARP;
    case ETHERTYPE_VLAN:
        return L3_PROTO_VLAN;
    case ETHERTYPE_QINQ:
        return L3_PROTO_QINQ;
    default:
        return L3_PROTO_UNKNOWN;
    }
}

/**
 * Maps an IP protocol number to an l4_proto_t enum value.
 * ipproto : raw protocol field from the IP header
 *
 * Returns the matching l4_proto_t, or L4_PROTO_UNKNOWN if unsupported.
 */
static l4_proto_t ipproto_to_l4(uint8_t ipproto)
{
    switch (ipproto)
    {
    case IPPROTO_TCP:
        return L4_PROTO_TCP;
    case IPPROTO_UDP:
        return L4_PROTO_UDP;
    case IPPROTO_ICMP:
        return L4_PROTO_ICMP;
    case IPPROTO_ICMPV6:
        return L4_PROTO_ICMPV6;
    default:
        return L4_PROTO_UNKNOWN;
    }
}

/* =========================================================================
 * Bounds check helper
 * ========================================================================= */

/**
 * Verify there are at least @needed bytes remaining in the buffer.
 *
 * len    : total buffer length
 * offset : current position in the buffer
 * needed : number of bytes required
 *
 * Returns true if enough bytes remain, false if the packet is truncated.
 */
static inline bool check_len(uint32_t len, uint32_t offset, uint32_t needed)
{
    return (len >= offset) && ((len - offset) >= needed);
}

/* =========================================================================
 * L4 parsers
 * ========================================================================= */

/**
 * Parse a TCP header.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated.
 */
static bool parse_tcp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    if (!check_len(len, *offset, sizeof(struct tcphdr)))
    {
        log_error("TCP header truncated%s", "");
        return false;
    }

    struct tcphdr tcp;
    memcpy(&tcp, (data + *offset), sizeof(struct tcphdr));

    out->src_port  = ntohs(tcp.th_sport);
    out->dst_port  = ntohs(tcp.th_dport);
    out->tcp_flags = tcp.th_flags;
    out->l4_proto  = L4_PROTO_TCP;

    *offset += (uint32_t)(tcp.th_off * sizeof(uint32_t));
    return true;
}

/**
 * Parse a UDP header.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated.
 */
static bool parse_udp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    if (!check_len(len, *offset, sizeof(struct udphdr)))
    {
        log_error("UDP header truncated%s", "");
        return false;
    }

    struct udphdr udp;
    memcpy(&udp, (data + *offset), sizeof(struct udphdr));

    out->src_port = ntohs(udp.uh_sport);
    out->dst_port = ntohs(udp.uh_dport);
    out->l4_proto = L4_PROTO_UDP;

    *offset += sizeof(struct udphdr);
    return true;
}

/**
 * Parse an ICMPv4 header.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated.
 */
static bool parse_icmp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    if (!check_len(len, *offset, sizeof(struct icmphdr)))
    {
        log_error("ICMP header truncated%s", "");
        return false;
    }

    struct icmphdr icmp;
    memcpy(&icmp, (data + *offset), sizeof(struct icmphdr));

    out->icmp_type = icmp.type;
    out->icmp_code = icmp.code;
    out->l4_proto  = L4_PROTO_ICMP;

    *offset += sizeof(struct icmphdr);
    return true;
}

/**
 * Parse an ICMPv6 header.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated.
 */
static bool parse_icmpv6(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    if (!check_len(len, *offset, sizeof(struct icmp6_hdr)))
    {
        log_error("ICMPv6 header truncated%s", "");
        return false;
    }

    struct icmp6_hdr icmp6;
    memcpy(&icmp6, (data + *offset), sizeof(struct icmp6_hdr));

    out->icmp_type = icmp6.icmp6_type;
    out->icmp_code = icmp6.icmp6_code;
    out->l4_proto  = L4_PROTO_ICMPV6;

    *offset += sizeof(struct icmp6_hdr);
    return true;
}

/* =========================================================================
 * L3 parsers
 * ========================================================================= */

/**
 * Parse an IPv4 header and dispatch to L4.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated or malformed.
 */
static bool parse_ipv4(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    if (!check_len(len, *offset, sizeof(struct ip)))
    {
        log_error("IPv4 header truncated%s", "");
        return false;
    }

    struct ip iph;
    memcpy(&iph, (data + *offset), sizeof(struct ip));

    out->ip_version = 4;
    out->ttl        = iph.ip_ttl;
    out->src_ip.v4  = iph.ip_src;
    out->dst_ip.v4  = iph.ip_dst;

    /* advance past the IP header (ihl is in 32-bit words) */
    *offset += (uint32_t)(iph.ip_hl * sizeof(uint32_t));

    l4_proto_t l4    = ipproto_to_l4(iph.ip_p);
    parse_fn   fnPtr = l4_table[l4];

    if (fnPtr)
    {
        return fnPtr(data, len, out, offset);
    }
    /* unsupported L4 — not an error, just stop here */
    out->l4_proto = L4_PROTO_UNKNOWN;
    return false;
}

/**
 * Parse an IPv6 header and dispatch to L4.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated.
 */
static bool parse_ipv6(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    if (!check_len(len, *offset, sizeof(struct ip6_hdr)))
    {
        log_error("IPv6 header truncated%s", "");
        return false;
    }

    struct ip6_hdr ip6;
    memcpy(&ip6, (data + *offset), sizeof(struct ip6_hdr));

    out->ip_version = 6;
    out->ttl        = ip6.ip6_hlim;
    out->src_ip.v6  = ip6.ip6_src;
    out->dst_ip.v6  = ip6.ip6_dst;

    *offset += sizeof(struct ip6_hdr);

    l4_proto_t l4    = ipproto_to_l4(ip6.ip6_nxt);
    parse_fn   fnPtr = l4_table[l4];

    if (fnPtr)
    {
        return fnPtr(data, len, out, offset);
    }

    out->l4_proto = L4_PROTO_UNKNOWN;
    return false;
}

/**
 * Parse an ARP header for IPv4 over Ethernet.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated.
 */
static bool parse_arp(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    /* ARP for IPv4 over Ethernet (RFC 826):
     *
     * offset  0: htype     (2)  hardware type         — 0x0001 Ethernet
     * offset  2: ptype     (2)  protocol type         — 0x0800 IPv4
     * offset  4: hlen      (1)  hardware address len  — 6
     * offset  5: plen      (1)  protocol address len  — 4
     * offset  6: opcode    (2)  request=1, reply=2
     * offset  8: sha       (6)  sender hardware addr
     * offset 14: spa       (4)  sender protocol addr
     * offset 18: tha       (6)  target hardware addr
     * offset 24: tpa       (4)  target protocol addr
     * total: 28 bytes
     */
    if (!check_len(len, *offset, ARP_HLEN))
    {
        log_error("ARP header truncated%s", "");
        return false;
    }

    const uint8_t *arp = data + *offset;

    out->l3_proto = L3_PROTO_ARP;
    out->l4_proto = L4_PROTO_UNKNOWN;

    uint16_t opcode;
    memcpy(&opcode, arp + ARP_OFFSET_OPCODE, sizeof(opcode));
    out->arp_opcode = ntohs(opcode);

    memcpy(out->arp_sender_mac, arp + ARP_OFFSET_SHA, ETH_ALEN);
    memcpy(&out->arp_sender_ip, arp + ARP_OFFSET_SPA, sizeof(out->arp_sender_ip));
    memcpy(out->arp_target_mac, arp + ARP_OFFSET_THA, ETH_ALEN);
    memcpy(&out->arp_target_ip, arp + ARP_OFFSET_TPA, sizeof(out->arp_target_ip));

    *offset += ARP_HLEN;
    return true;
}

/* =========================================================================
 * L2 parser
 * ========================================================================= */

/**
 * Parse an Ethernet II header including optional VLAN tags.
 *
 * data   : raw packet buffer
 * len    : total buffer length
 * out    : destination parsed_pkt_t
 * offset : current byte offset into data, updated on return
 *
 * Returns true on success, false if truncated or malformed.
 */
static bool parse_eth(const uint8_t *data, uint32_t len, parsed_pkt_t *out, uint32_t *offset)
{
    if (!check_len(len, *offset, ETH_HLEN))
    {
        log_error("Ethernet header truncated%s", "");
        return false;
    }

    memcpy(out->dst_mac, data + *offset, ETH_ALEN);
    memcpy(out->src_mac, data + *offset + ETH_ALEN, ETH_ALEN);

    /* read ethertype at its fixed position (bytes 12-13) before advancing */
    uint16_t ethertype = ntohs(*(const uint16_t *)(data + *offset + 2 * ETH_ALEN));
    *offset += ETH_HLEN;

    /* Double tagged frame, read the outer tag first */
    if (ethertype == ETHERTYPE_QINQ)
    {
        if (!check_len(len, *offset, ETH_VLAN_HLEN))
        {
            log_error("QinQ outer tag truncated%s", "");
            return false;
        }
        uint16_t tci  = ntohs(*(const uint16_t *)(data + *offset));
        out->vlan_pcp = (tci >> VLAN_PCP_SHIFT) & VLAN_PCP_MASK;
        out->vlan_id  = tci & VLAN_ID_MASK;

        /* inner ethertype follows the 2-byte TCI */
        ethertype = ntohs(*(const uint16_t *)(data + *offset + 2));
        *offset += ETH_VLAN_HLEN;
    }

    /* read VLAN tag, inner tag if it is double tagged */
    if (ethertype == ETHERTYPE_VLAN)
    {
        if (!check_len(len, *offset, ETH_VLAN_HLEN))
        {
            log_error("VLAN tag truncated%s", "");
            return false;
        }
        uint16_t tci = ntohs(*(const uint16_t *)(data + *offset));

        /* if we already have an outer vlan_id this is the inner tag (QinQ) */
        if (out->vlan_id)
        {
            out->inner_vlan_pcp = (tci >> VLAN_PCP_SHIFT) & VLAN_PCP_MASK;
            out->inner_vlan_id  = tci & VLAN_ID_MASK;
        }
        else
        {
            out->vlan_pcp = (tci >> VLAN_PCP_SHIFT) & VLAN_PCP_MASK;
            out->vlan_id  = tci & VLAN_ID_MASK;
        }

        /* next ethertype follows the 2-byte TCI */
        ethertype = ntohs(*(const uint16_t *)(data + *offset + 2));
        *offset += ETH_VLAN_HLEN;
    }

    /* parse L3 */
    l3_proto_t l3 = ethertype_to_l3(ethertype);
    out->l3_proto = l3;

    parse_fn fnPtr = l3_table[l3];
    if (fnPtr)
    {
        return fnPtr(data, len, out, offset);
    }

    /* unsupported L3 ethertype — not an error */
    return false;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

/**
 * Parse a raw captured frame into a parsed_pkt_t.
 *
 * slot  :  raw packet slot from the ring buffer
 * out   :  destination struct to fill
 *
 * Returns true  on success, with @out populated.
 * Returns false if the packet is truncated or malformed.
 */
bool parse_packet(const pkt_slot_t *slot, parsed_pkt_t *out)
{
    memset(out, 0, sizeof(*out));

    out->ts      = slot->ts;
    out->caplen  = slot->caplen;
    out->origlen = slot->origlen;

    uint32_t offset = 0;
    return parse_eth(slot->data, slot->caplen, out, &offset);
}

/* =========================================================================
 * Print
 * ========================================================================= */

static const char *tcp_flags_str(uint8_t flags)
{
    static char buf[32];
    int         pos = 0;

    if (flags & TH_SYN)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "SYN ");
    if (flags & TH_ACK)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "ACK ");
    if (flags & TH_FIN)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "FIN ");
    if (flags & TH_RST)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "RST ");
    if (flags & TH_PUSH)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "PSH ");
    if (flags & TH_URG)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "URG ");

    if (pos == 0)
        snprintf(buf, sizeof(buf), "NONE");
    else if (pos > 0 && buf[pos - 1] == ' ')
        buf[pos - 1] = '\0'; /* trim trailing space */

    return buf;
}

/**
 * Print parsed packet details to stdout.
 *
 * pkt :   parsed packet from parse_packet()
 */
void print_packet(const parsed_pkt_t *pkt)
{
    char src_ip[INET6_ADDRSTRLEN] = "-";
    char dst_ip[INET6_ADDRSTRLEN] = "-";

    /* format timestamp */
    printf("%ld.%06ld", (long)pkt->ts.tv_sec, (long)pkt->ts.tv_usec);

    /* L2 */
    printf(" | %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x", pkt->src_mac[0],
           pkt->src_mac[1], pkt->src_mac[2], pkt->src_mac[3], pkt->src_mac[4], pkt->src_mac[5],
           pkt->dst_mac[0], pkt->dst_mac[1], pkt->dst_mac[2], pkt->dst_mac[3], pkt->dst_mac[4],
           pkt->dst_mac[5]);

    if (pkt->vlan_id)
        printf(" | VLAN %u pcp %u", pkt->vlan_id, pkt->vlan_pcp);
    if (pkt->inner_vlan_id)
        printf(".%u pcp %u", pkt->inner_vlan_id, pkt->inner_vlan_pcp);

    /* L3 */
    switch (pkt->l3_proto)
    {
    case L3_PROTO_IPV4:
        inet_ntop(AF_INET, &pkt->src_ip.v4, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &pkt->dst_ip.v4, dst_ip, sizeof(dst_ip));
        printf(" | IPv4 %s -> %s TTL %u", src_ip, dst_ip, pkt->ttl);
        break;
    case L3_PROTO_IPV6:
        inet_ntop(AF_INET6, &pkt->src_ip.v6, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &pkt->dst_ip.v6, dst_ip, sizeof(dst_ip));
        printf(" | IPv6 %s -> %s Hop %u", src_ip, dst_ip, pkt->ttl);
        break;
    case L3_PROTO_ARP:
    {
        char sender_ip[INET_ADDRSTRLEN];
        char target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt->arp_sender_ip, sender_ip, sizeof(sender_ip));
        inet_ntop(AF_INET, &pkt->arp_target_ip, target_ip, sizeof(target_ip));

        const char *op = pkt->arp_opcode == ARP_OP_REQUEST ? "request"
                         : pkt->arp_opcode == ARP_OP_REPLY ? "reply"
                                                           : "unknown";

        printf(" | ARP %s who-has %s tell %s", op, target_ip, sender_ip);
        break;
    }
    default:
        printf(" | L3 unknown");
        break;
    }

    /* L4 */
    switch (pkt->l4_proto)
    {
    case L4_PROTO_TCP:
        printf(" | TCP %u -> %u [%s]", pkt->src_port, pkt->dst_port, tcp_flags_str(pkt->tcp_flags));
        break;
    case L4_PROTO_UDP:
        printf(" | UDP %u -> %u", pkt->src_port, pkt->dst_port);
        break;
    case L4_PROTO_ICMP:
        printf(" | ICMP type %u code %u", pkt->icmp_type, pkt->icmp_code);
        break;
    case L4_PROTO_ICMPV6:
        printf(" | ICMPv6 type %u code %u", pkt->icmp_type, pkt->icmp_code);
        break;
    default:
        break;
    }

    /* length */
    printf(" | len %u", pkt->caplen);
    if (pkt->caplen != pkt->origlen)
        printf(" (orig %u)", pkt->origlen);

    printf("\n");
}