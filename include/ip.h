#ifndef IP_H
#define IP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#define IP_ALEN 4
#define IP_HLEN 20

#define IP_TYPE_TCP      6
#define IP_TYPE_UDP      17

#define ip_hstoa(a) \
	(ip_ntoa(((const struct ip_header *) (a))->saddr))

#define ip_hdtoa(a) \
	(ip_ntoa(((const struct ip_header *) (a))->daddr))

struct ip_header {
	unsigned int ihl:4;
	unsigned int version:4;
	unsigned int ecn:2;
    unsigned int dscp:6;
	uint16_t tot_len;
	uint16_t id;
    uint16_t flags_frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint8_t saddr[IP_ALEN];
	uint8_t daddr[IP_ALEN];
};

static char *ip_ntoa(const uint8_t *const a)
{
	static char x[16];
	sprintf(x, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
	return x;
}

#ifdef __cplusplus
}
#endif

#endif
