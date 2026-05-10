#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>

#include "capture.h"
#include "parser.h"
#include "ringbuff.h"
#include "log.h"

/** After calling getopt_long, the value of the argument is stored in this variable.
 * However, the value is overwritten after every call to getopt_long, so copy the value
 * before calling getopt_long again.
 */
extern char *optarg;

/* -------------------------------------------------------------------------
 * Globals
 * ------------------------------------------------------------------------- */

static pcap_t   *g_handle = NULL;
static ring_t   *g_ring   = NULL;
static pthread_t g_parser_thread;

/* -------------------------------------------------------------------------
 * Signal handler
 * ------------------------------------------------------------------------- */

static void on_sigint(int sig)
{
    (void)sig;
    if (g_handle)
    {
        pcap_breakloop(g_handle);
    }
}

/**
 * Drains the ring buffer, parses each frame and prints it.
 * Exits when ring_pop() returns false (ring shut down and drained).
 */

static void *parser_thread(void *arg)
{
    ring_t      *ring = (ring_t *)arg;
    pkt_slot_t   slot;
    parsed_pkt_t pkt;

    while (ring_pop(ring, &slot))
    {
        if (parse_packet(&slot, &pkt))
        {
            print_packet(&pkt);
        }
        else
        {
            ring->unknown++;
        }
    }

    return NULL;
}

/**
 * CLI
 */

/* clang-format off */
static struct option longopts[] = {
    {"interface",   required_argument,  NULL,   'i'},
    {"count",       required_argument,  NULL,   'c'},
    {NULL,          0,                  NULL,    0}
};
/* clang-format on */

static void print_usage(const char *prog)
{
    log_info("Usage: %s -i <interface> [-c <count>]", prog);
}

int main(int argc, char *argv[])
{
    char            *ifname = NULL;
    int              count  = 0;
    int              op;
    struct pcap_stat stats = {0};

    if (argc < 2)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    while ((op = getopt_long(argc, argv, "i:c:", longopts, NULL)) != -1)
    {
        switch (op)
        {
        case 'i':
            ifname = optarg;
            break;
        case 'c':
            count = atoi(optarg);
            break;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!ifname)
    {
        log_error("interface (-i) is mandatory%s", "");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* ring buffer */
    g_ring = ring_init();
    if (!g_ring)
    {
        log_error("Failed to create ring buffer%s", "");
        return EXIT_FAILURE;
    }

    /* capture handle */
    g_handle = capture_open(ifname);
    if (!g_handle)
    {
        ring_destroy(g_ring);
        return EXIT_FAILURE;
    }

    /* SIGINT handler */
    signal(SIGINT, on_sigint);

    /* parser thread */
    if (pthread_create(&g_parser_thread, NULL, parser_thread, g_ring) != 0)
    {
        log_error("Failed to create parser thread%s", "");
        capture_close(g_handle);
        ring_destroy(g_ring);
        return EXIT_FAILURE;
    }

    /* capture (blocks until pcap_breakloop or count reached) */
    log_info("Starting capture on '%s' (count=%d)", ifname, count);
    capture_start(g_handle, g_ring, count);

    /* graceful shutdown sequence:
     *   1. pcap_breakloop() already called (by SIGINT or count reached)
     *   2. ring_shutdown() unblocks parser thread if waiting on condvar
     *   3. pthread_join() wait for parser thread to drain and exit
     *   4. print stats
     *   5. free resources
     */
    ring_shutdown(g_ring);
    pthread_join(g_parser_thread, NULL);

    (void)capture_stats(g_handle, &stats);

    log_info("Capture complete");
    log_info("libpcap stats: received: %u packets, dropped: %u packets, if-dropped: %u packets",
             stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
    log_info("ethdump stats: captured: %lu packets, dropped: %lu packets, processed: %lu packets, unknown: %lu packets",
             g_ring->captured, g_ring->dropped, g_ring->processed, g_ring->unknown);

    capture_close(g_handle);
    ring_destroy(g_ring);

    return EXIT_SUCCESS;
}