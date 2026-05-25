#include <stdint.h>

typedef struct{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ethertype;
} ethernet_header;

typedef struct{
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t src_ip;
	uint32_t dst_ip;
} ip_header;

typedef struct{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t offset_reserved;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent;
} tcp_header;
