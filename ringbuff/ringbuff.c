#include "ringbuff.h"

#include <stdlib.h>
#include <string.h>

/**
 * Internal helpers
 */

static inline bool ring_is_full(const ring_t *r)
{
    /** The head and tail are free running counters counting upto a max value of
     * UINT32_MAX. So there are two cases, one without wraparound and another with
     * wraparound.
     *
     * case 1: No wraparound i.e head > tail, ex:
     * head = 0x1000, tail = 0, head - tail = RING_SIZE
     *
     * case 2: Wraparound i.e tail > head, ex:
     * Non Full case:
     * head = 0x100, tail = 0xFFFFFF00, head - tail = 0x200 = 512 < RING_SIZE
     *
     * Full case:
     * head = 0xF00, tail = 0xFFFFFF00, head - tail = 0x1000 = 4096 == RING_SIZE
     *
     */
    return (r->head - r->tail) == RING_SIZE;
}

static inline bool ring_is_empty(const ring_t *r)
{
    return r->head == r->tail;
}

/**
 * Initializes the ring buffer. Must be called before any other ring_* function.
 * Returns a pointer to the ring buffer on success, NULL on failure.
 */

ring_t *ring_init(void)
{
    ring_t *r = calloc(1, sizeof(ring_t));
    if (!r)
        return NULL;

    r->head     = 0;
    r->tail     = 0;
    r->dropped  = 0;
    r->shutdown = false;

    if (pthread_mutex_init(&r->mutex, NULL) != 0)
    {
        free(r);
        return NULL;
    }

    if (pthread_cond_init(&r->not_empty, NULL) != 0)
    {
        pthread_mutex_destroy(&r->mutex);
        free(r);
        return NULL;
    }

    return r;
}

/**
 * Destroys the ring buffer and releases all resources. Must not be called while
 * other threads are still using the ring.
 */

void ring_destroy(ring_t *r)
{
    if (!r)
        return;

    pthread_cond_destroy(&r->not_empty);
    pthread_mutex_destroy(&r->mutex);
    free(r);
}

/**
 * Push a packet into the ring buffer.
 * Returns true if the packet was successfully pushed, false if the ring was full
 * and the packet was dropped. The counter dropped is incremented in the latter case.
 */

bool ring_push(ring_t *r, struct timeval ts, const uint8_t *data, uint32_t caplen, uint32_t origlen)
{
    pthread_mutex_lock(&r->mutex);

    r->captured++;

    if (ring_is_full(r))
    {
        r->dropped++;
        pthread_mutex_unlock(&r->mutex);
        return false;
    }

    pkt_slot_t *slot = &r->slots[r->head & RING_MASK];
    slot->ts         = ts;
    slot->caplen     = caplen;
    slot->origlen    = origlen;
    memcpy(slot->data, data, caplen > ETH_FRAME_MAX ? ETH_FRAME_MAX : caplen);

    r->head++;

    pthread_cond_signal(&r->not_empty);
    pthread_mutex_unlock(&r->mutex);

    return true;
}

/**
 * Pops a packet from the ring buffer. Blocks on not_empty when the ring is empty.
 * The counter processed is incremented when a packet is successfully popped.
 * Returns true if a packet was successfully popped, false if shutdown has been
 * requested and the ring is drained.
 */

bool ring_pop(ring_t *r, pkt_slot_t *out)
{
    pthread_mutex_lock(&r->mutex);

    /* wait until there is something to consume or we are shutting down */
    while (ring_is_empty(r) && !r->shutdown)
    {
        pthread_cond_wait(&r->not_empty, &r->mutex);
    }

    if (ring_is_empty(r))
    {
        pthread_mutex_unlock(&r->mutex);
        return false;
    }

    *out = r->slots[r->tail & RING_MASK];
    r->tail++;
    r->processed++;
    pthread_mutex_unlock(&r->mutex);

    return true;
}

/**
 * Fucntion to signal shutdown has been initiated. Wake up the parser thread if
 * it is sleeping on the condition variable. After this is called, ring_pop()
 * will return false once the ring is drained.
 */

void ring_shutdown(ring_t *r)
{
    pthread_mutex_lock(&r->mutex);
    r->shutdown = true;
    pthread_cond_signal(&r->not_empty); /* wake decode thread if sleeping  */
    pthread_mutex_unlock(&r->mutex);
}

/**
 * Returns the number of packets dropped due to ring buffer overflow.
 */

uint64_t ring_dropped(const ring_t *r)
{
    return r->dropped;
}