#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

#include "ringbuff.h"

pcap_t *capture_open(const char *iface);
void capture_start(pcap_t *handle, ring_t *ring, int count);
bool capture_stats(pcap_t *handle, struct pcap_stat *stats);
void capture_close(pcap_t *handle);

#endif /* CAPTURE_H */