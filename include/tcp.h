#ifndef TCP_H
#define TCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define TCP_HLEN 20

struct tcp_header {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
	unsigned int ns:1;
	unsigned int res:3;
	unsigned int doff:4;
	union {
		struct {
			unsigned int fin:1;
			unsigned int syn:1;
			unsigned int rst:1;
			unsigned int psh:1;
			unsigned int ack:1;
			unsigned int urg:1;
			unsigned int ece:1;
			unsigned int cwr:1;
		} __attribute__((packed));
		uint8_t lb_flags;
	};
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
};

#ifdef __cplusplus
}
#endif

#endif
