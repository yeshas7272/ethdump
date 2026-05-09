#ifndef RINGBUF_H
#define RINGBUF_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdatomic.h>

/**
 * Constants
 */

#define RING_SIZE 4096u /* must be a power of 2               */
#define RING_MASK (RING_SIZE - 1u)
#define ETH_FRAME_MAX 1522u /* 802.3 max frame size with VLAN tags    */

/** The implementation of ring_push and ring_pop assumes RING_SIZE is set to a power of 2 as
 * it uses AND operation instead of MODULO. MODULO operation compile into a division instruction
 * which is the most expensive arithmetic operation. Using a power of 2 allows us to use bitwise
 * AND which is much faster.
 * For example, if RING_SIZE is 4096 (0x1000), then RING_MASK is 4095 (0x0FFF). So when we do
 * head & RING_MASK, it effectively gives us head % RING_SIZE but much faster.
 */
_Static_assert((RING_SIZE & RING_MASK) == 0, "RING_SIZE must be a power of 2");

/**
 * Packet slot
 *
 * One captured frame. data[] is 64-byte aligned so that the struct itself
 * sits at a cache-line boundary.
 */

typedef struct
{
    struct timeval ts;
    uint32_t       caplen;
    uint32_t       origlen;
    uint8_t        data[ETH_FRAME_MAX] __attribute__((aligned(64)));
} pkt_slot_t;

/**
 * Two-thread producer/consumer buffer protected by a mutex.
 * condvar not_empty: parser thread waits here when ring is empty.
 * Producer never blocks: full ring means drop, never wait.
 */

typedef struct
{
    pkt_slot_t      slots[RING_SIZE];
    uint32_t        head;      /* next slot to write (producer)      */
    uint32_t        tail;      /* next slot to read  (consumer)      */
    uint64_t        dropped;   /* packets lost while ring was full   */
    uint64_t        captured;  /* total packets pushed since init    */
    uint64_t        processed; /* total packets processed            */
    uint64_t        unknown;   /* packets that didnt match any known protocols      */
    bool            shutdown;  /* signals parser thread to exit      */
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty; /* signalled by producer on push      */
} ring_t;

/**
 * APIs
 */
ring_t  *ring_init(void);
void     ring_destroy(ring_t *r);
bool     ring_push(ring_t *r, struct timeval ts, const uint8_t *data, uint32_t caplen,
                   uint32_t origlen);
bool     ring_pop(ring_t *r, pkt_slot_t *out);
void     ring_shutdown(ring_t *r);
uint64_t ring_dropped(const ring_t *r);

#endif /* RINGBUF_H */