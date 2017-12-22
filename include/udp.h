#ifndef UDP_H
#define UDP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define UDP_HLEN 8

struct udp_header {
	uint16_t sport;
	uint16_t dport;
	uint16_t ulen;
	uint16_t sum;
};

#ifdef __cplusplus
}
#endif

#endif
