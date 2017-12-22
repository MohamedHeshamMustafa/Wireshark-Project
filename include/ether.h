#ifndef ETHER_H
#define ETHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#define ETHER_ALEN	6
#define ETHER_HLEN	14

#define ETHER_TYPE_IP  0x0800

#define ether_hstoa(a) \
	(ether_ntoa(((const struct ether_header *) (a))->shost))

#define ether_hdtoa(a) \
	(ether_ntoa(((const struct ether_header *) (a))->dhost))

struct ether_header {
	uint8_t  dhost[ETHER_ALEN];
	uint8_t  shost[ETHER_ALEN];
	uint16_t type;
};

static char *ether_ntoa(const uint8_t *const a)
{
    static char x[18];
	sprintf(x, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		a[0], a[1], a[2], a[3], a[4], a[5]
	);
	return x;
}

#ifdef __cplusplus
}
#endif

#endif
