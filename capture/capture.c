#include "log.h"
#include "capture.h"

#define CAPTURE_SNAPLEN ETH_FRAME_MAX /* max bytes captured per packet          */
#define CAPTURE_PROMISC 1             /* promiscuous mode on                    */
#define CAPTURE_TIMEOUT_MS 1000       /* read timeout in milliseconds           */

/**
 * pcap_callback
 *
 * Called by pcap_loop() for every captured packet.
 *
 * - Must return as fast as possible, pcap_loop() cannot process the
 *   next packet until this returns.
 * - bytes is only valid for the duration of this call. libpcap reuses
 *   the underlying PACKET_MMAP buffer after we return, so memcpy into
 *   the ring slot is mandatory.
 * - user is the ring_t * passed to pcap_loop() cast to u_char *.
 */

static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
    ring_t *ring = (ring_t *)user;

    if (!ring_push(ring, hdr->ts, bytes, hdr->caplen, hdr->len))
    {
        log_error("Ring full — packet dropped (caplen=%u)", hdr->caplen);
    }
}

/**
 * capture_open
 */

pcap_t *capture_open(const char *iface)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle =
        pcap_open_live(iface, CAPTURE_SNAPLEN, CAPTURE_PROMISC, CAPTURE_TIMEOUT_MS, errbuf);
    if (!handle)
    {
        log_error("Failed to open interface '%s': %s", iface, errbuf);
        return NULL;
    }

    log_info("Opened interface '%s' (snaplen=%d, promisc=%d)", iface, CAPTURE_SNAPLEN,
             CAPTURE_PROMISC);

    return handle;
}

/**
 * capture_start
 */

void capture_start(pcap_t *handle, ring_t *ring, int count)
{
    int ret = pcap_loop(handle, count, pcap_callback, (u_char *)ring);

    if (ret == PCAP_ERROR)
    {
        log_error("pcap_loop failed: %s", pcap_geterr(handle));

        /* ret == -2 means pcap_breakloop() was called — clean shutdown, not an error */
    }
}

bool capture_stats(pcap_t *handle, struct pcap_stat *stats)
{
    if (pcap_stats(handle, stats) == -1)
    {
        log_error("Failed to get capture stats: %s", pcap_geterr(handle));
        return false;
    }
    return true;
}

/**
 * capture_close
 */

void capture_close(pcap_t *handle)
{
    if (handle)
    {
        pcap_close(handle);
    }
}