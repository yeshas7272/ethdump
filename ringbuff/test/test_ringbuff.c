#include "unity.h"
#include "ringbuff.h"

#include <pthread.h>
#include <string.h>
#include <time.h>

/* =========================================================================
 * setUp / tearDown
 * ========================================================================= */

static ring_t *g_ring;

void setUp(void)
{
    g_ring = ring_init();
}

void tearDown(void)
{
    ring_destroy(g_ring);
    g_ring = NULL;
}

/* =========================================================================
 * Helpers
 * ========================================================================= */

static struct timeval make_ts(long sec)
{
    struct timeval ts = {.tv_sec = sec, .tv_usec = 0};
    return ts;
}

/* =========================================================================
 * Tests — init
 * ========================================================================= */

void test_ring_init_zero_state(void)
{
    TEST_ASSERT_NOT_NULL(g_ring);
    TEST_ASSERT_EQUAL_UINT32(0, g_ring->head);
    TEST_ASSERT_EQUAL_UINT32(0, g_ring->tail);
    TEST_ASSERT_EQUAL_UINT64(0, g_ring->captured);
    TEST_ASSERT_EQUAL_UINT64(0, g_ring->dropped);
    TEST_ASSERT_EQUAL_UINT64(0, g_ring->processed);
    TEST_ASSERT_FALSE(g_ring->shutdown);
}

/* =========================================================================
 * Tests — push
 * ========================================================================= */

void test_ring_push_increments_captured(void)
{
    uint8_t data[4] = {1, 2, 3, 4};
    ring_push(g_ring, make_ts(0), data, sizeof(data), sizeof(data));
    TEST_ASSERT_EQUAL_UINT64(1, g_ring->captured);
    TEST_ASSERT_EQUAL_UINT64(0, g_ring->dropped);
}

void test_ring_full_returns_false(void)
{
    uint8_t data[1] = {0};
    unsigned pushed  = 0;

    for (unsigned i = 0; i < RING_SIZE + 1; i++)
    {
        if (ring_push(g_ring, make_ts(0), data, 1, 1))
            pushed++;
    }

    TEST_ASSERT_EQUAL_UINT(RING_SIZE, pushed);
}

void test_ring_dropped_counter(void)
{
    uint8_t data[1] = {0};

    for (unsigned i = 0; i < RING_SIZE + 5; i++)
        ring_push(g_ring, make_ts(0), data, 1, 1);

    TEST_ASSERT_EQUAL_UINT64(RING_SIZE, g_ring->captured);
    TEST_ASSERT_EQUAL_UINT64(5, g_ring->dropped);
    TEST_ASSERT_EQUAL_UINT64(5, ring_dropped(g_ring));
}

/* =========================================================================
 * Tests — push / pop
 * ========================================================================= */

void test_ring_push_pop_roundtrip(void)
{
    uint8_t        data[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0xFF};
    struct timeval ts      = {.tv_sec = 12345, .tv_usec = 999};

    TEST_ASSERT_TRUE(ring_push(g_ring, ts, data, sizeof(data), sizeof(data) + 4));

    ring_shutdown(g_ring);

    pkt_slot_t slot;
    TEST_ASSERT_TRUE(ring_pop(g_ring, &slot));

    TEST_ASSERT_EQUAL_UINT32(sizeof(data), slot.caplen);
    TEST_ASSERT_EQUAL_UINT32(sizeof(data) + 4, slot.origlen);
    TEST_ASSERT_EQUAL(ts.tv_sec, slot.ts.tv_sec);
    TEST_ASSERT_EQUAL(ts.tv_usec, slot.ts.tv_usec);
    TEST_ASSERT_EQUAL_MEMORY(data, slot.data, sizeof(data));
}

void test_ring_fifo_order(void)
{
    const int N = 8;

    for (int i = 0; i < N; i++)
    {
        uint8_t data[1] = {(uint8_t)i};
        ring_push(g_ring, make_ts(i), data, 1, 1);
    }

    ring_shutdown(g_ring);

    pkt_slot_t slot;
    for (int i = 0; i < N; i++)
    {
        TEST_ASSERT_TRUE(ring_pop(g_ring, &slot));
        TEST_ASSERT_EQUAL_UINT8((uint8_t)i, slot.data[0]);
        TEST_ASSERT_EQUAL(i, slot.ts.tv_sec);
    }

    TEST_ASSERT_FALSE(ring_pop(g_ring, &slot));
}

void test_ring_processed_counter(void)
{
    const int N    = 4;
    uint8_t   data[1] = {0};

    for (int i = 0; i < N; i++)
        ring_push(g_ring, make_ts(0), data, 1, 1);

    ring_shutdown(g_ring);

    pkt_slot_t slot;
    while (ring_pop(g_ring, &slot))
        ;

    TEST_ASSERT_EQUAL_UINT64(N, g_ring->processed);
}

void test_ring_slot_reuse(void)
{
    /* Push and pop RING_SIZE items to exercise the slot index wraparound */
    pkt_slot_t slot;

    for (unsigned i = 0; i < RING_SIZE; i++)
    {
        uint8_t data[1] = {(uint8_t)(i & 0xFF)};
        TEST_ASSERT_TRUE(ring_push(g_ring, make_ts((long)i), data, 1, 1));
    }

    ring_shutdown(g_ring);

    unsigned count = 0;
    while (ring_pop(g_ring, &slot))
    {
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(count & 0xFF), slot.data[0]);
        count++;
    }

    TEST_ASSERT_EQUAL_UINT(RING_SIZE, count);
    TEST_ASSERT_EQUAL_UINT64(RING_SIZE, g_ring->captured);
    TEST_ASSERT_EQUAL_UINT64(RING_SIZE, g_ring->processed);
    TEST_ASSERT_EQUAL_UINT64(0, g_ring->dropped);
}

/* =========================================================================
 * Tests — shutdown
 * ========================================================================= */

void test_ring_shutdown_empty_returns_false(void)
{
    ring_shutdown(g_ring);
    pkt_slot_t slot;
    TEST_ASSERT_FALSE(ring_pop(g_ring, &slot));
}

void test_ring_shutdown_drains_remaining(void)
{
    const int N    = 3;
    uint8_t   data[1] = {0};

    for (int i = 0; i < N; i++)
        ring_push(g_ring, make_ts(i), data, 1, 1);

    ring_shutdown(g_ring);

    pkt_slot_t slot;
    int        count = 0;
    while (ring_pop(g_ring, &slot))
        count++;

    TEST_ASSERT_EQUAL_INT(N, count);
    TEST_ASSERT_EQUAL_UINT64(N, g_ring->processed);
}

/* =========================================================================
 * Tests — threading (condvar signal)
 * ========================================================================= */

typedef struct
{
    ring_t  *ring;
    uint8_t  expected_byte;
    bool     result;
} consumer_arg_t;

static void *consumer_fn(void *arg)
{
    consumer_arg_t *ca = arg;
    pkt_slot_t      slot;
    if (!ring_pop(ca->ring, &slot))
    {
        ca->result = false;
        return NULL;
    }
    ca->result = (slot.data[0] == ca->expected_byte);
    return NULL;
}

void test_ring_threaded_signal(void)
{
    consumer_arg_t arg = {.ring = g_ring, .expected_byte = 0x42, .result = false};

    pthread_t tid;
    pthread_create(&tid, NULL, consumer_fn, &arg);

    /* Give the consumer thread time to block on the condvar */
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000}; /* 20ms */
    nanosleep(&delay, NULL);

    uint8_t data[1] = {0x42};
    ring_push(g_ring, make_ts(0), data, 1, 1);

    pthread_join(tid, NULL);
    TEST_ASSERT_TRUE(arg.result);
}

/* =========================================================================
 * main
 * ========================================================================= */

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_ring_init_zero_state);

    RUN_TEST(test_ring_push_increments_captured);
    RUN_TEST(test_ring_full_returns_false);
    RUN_TEST(test_ring_dropped_counter);

    RUN_TEST(test_ring_push_pop_roundtrip);
    RUN_TEST(test_ring_fifo_order);
    RUN_TEST(test_ring_processed_counter);
    RUN_TEST(test_ring_slot_reuse);

    RUN_TEST(test_ring_shutdown_empty_returns_false);
    RUN_TEST(test_ring_shutdown_drains_remaining);

    RUN_TEST(test_ring_threaded_signal);

    return UNITY_END();
}
