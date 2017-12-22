#ifndef PACKET_H
#define PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pcap.h>

#include "ether.h"

#include "ip.h"

#include "tcp.h"
#include "udp.h"

#define bswap16(x) \
	((uint16_t) ((x) << 8 | (x) >> 8))

#define bswap32(x) \
	((uint32_t) ((x) >> 24 | ((x) >> 8 & 0xFF00) | ((x) << 8 & 0xFF0000) | (x) << 24))

#define tdiff(a, b) \
	(((a).tv_sec - (b).tv_sec) + 1e-9f*((a).tv_nsec - (b).tv_nsec))

enum {
	TYPE_UNKNOWN,
	TYPE_IP,
	TYPE_TCP,
	TYPE_UDP,
	TYPE_HTTP,
	TYPE_SZ
};

static const char *const stypes[TYPE_SZ] = {
	"UNKNOWN",
	"IP",
	"TCP",
	"UDP",
	"HTTP",
};

static const char *const ltypes[TYPE_SZ] = {
	"UNKNOWN",
	"Internet Protocol Version 4",
	"Transmission Control Protocol",
	"User Datagram Protocol",
	"Hypertext Transfer Protocol",
};

typedef uint16_t type_t;

typedef struct {
    int16_t sz;
    type_t type;
    uint8_t *raw;
} layer_t;

typedef struct {
	size_t no;
	struct timespec ts;
	uint32_t len;

	union {
        struct ether_header eth;
        uint8_t eth_raw[ETHER_HLEN];
    };

    layer_t net;
	layer_t trans;
	layer_t app;
} eth_packet_t;

struct ud {
    uint32_t *const npackets;
	eth_packet_t *const p;
	const pcap_handler post;
	uint8_t *const post_user;
};

void process_packet(uint8_t *ud, const struct pcap_pkthdr *, const uint8_t *);
void free_packet(eth_packet_t *p);
const char *get_protocol(const eth_packet_t *p);

#ifdef __cplusplus
}
#endif

#endif
