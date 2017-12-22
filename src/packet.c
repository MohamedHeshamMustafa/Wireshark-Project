#include <stdlib.h>
#include <string.h>

#include "packet.h"

static int process_ip(const uint8_t **, layer_t *);
static int process_tcp(const uint8_t **, layer_t *);
static int process_udp(const uint8_t **, layer_t *);
static void process_app(const char **, layer_t *, uint32_t, int);

void process_packet(uint8_t *u, const struct pcap_pkthdr *const h, const uint8_t *const b)
{
    struct ud *const ud = (struct ud *) u;
    const uint8_t *nb = b;
	eth_packet_t *const p = ud->p;
	int tnext = -1;

	p->no  = ++*ud->npackets;
	p->ts.tv_sec = h->ts.tv_sec;
	p->ts.tv_nsec = 1000L*h->ts.tv_usec;
	p->len = h->caplen;
	p->eth = *((const struct ether_header *) nb);
	nb += ETHER_HLEN;

	switch(bswap16(p->eth.type)) {
		case ETHER_TYPE_IP: tnext = process_ip(&nb, &p->net); break;
	}

	switch (tnext) {
		case IP_TYPE_TCP: process_tcp(&nb, &p->trans); break;
		case IP_TYPE_UDP: process_udp(&nb, &p->trans); break;
	}

	uint32_t sz = p->len - (nb - b);
	if(sz)
    	process_app((const char **) &nb, &p->app, sz, p->trans.sz != 0);

	if(ud->post != NULL)
    	ud->post(ud->post_user, h, b);
}

void free_packet(eth_packet_t *p)
{
	if(p->app.raw != NULL) {
		free(p->app.raw);
		p->app.raw = NULL;
	}

	if(p->trans.raw != NULL) {
		free(p->trans.raw);
		p->trans.raw = NULL;
	}

	if(p->net.raw != NULL) {
		free(p->net.raw);
		p->net.raw = NULL;
	}
}

const char *get_protocol(const eth_packet_t *p)
{
	static char x[7];
	if(p->app.type)
		return stypes[p->app.type];
	else if(p->trans.type)
		return stypes[p->trans.type];
	else if(p->net.type)
		return stypes[p->net.type];
	else
		sprintf(x, "0x%hX", p->eth.type);
	return x;
}

static int process_ip(const uint8_t **b, layer_t *l)
{
	const struct ip_header *h = ((const struct ip_header *) *b);

	l->sz   = 4*h->ihl;
	l->type = TYPE_IP;
	l->raw  = memcpy(malloc(l->sz), *b, l->sz);

	*b += l->sz;
	return h->protocol;
}

static int process_tcp(const uint8_t **b, layer_t *l)
{
	const struct tcp_header *h = ((const struct tcp_header *) *b);

	l->sz   = 4*h->doff;
	l->type = TYPE_TCP;
	l->raw  = memcpy(malloc(l->sz), *b, l->sz);

	*b += l->sz;
	return 0;
}

static int process_udp(const uint8_t **b, layer_t *l)
{
    const struct udp_header *h = ((const struct udp_header *) *b);

    l->sz   = UDP_HLEN;
    l->type = TYPE_UDP;
    l->raw  = memcpy(malloc(l->sz), *b, l->sz);

    *b += l->sz;
    return h->ulen;
}

static void process_app(const char **b, layer_t *l, uint32_t sz, int g)
{
    l->sz = sz;
    l->raw  = memcpy(malloc(l->sz), *b, l->sz);
    *b += l->sz;

    if(g) {
        const char *s = (const char *) *b - sz;
        while(s+5 < *b && (s = memchr(s, 'H', *b - s)) != NULL && strncmp(s, "HTTP/", 5)) ++s;
        if(s+5 < *b && s != NULL)
            l->type = TYPE_HTTP;
    }
}
