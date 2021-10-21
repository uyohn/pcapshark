

#include <pcap/pcap.h>
#include <stdint.h>
#include <sys/types.h>


// ERR CONSTS

#define FILE_OPEN_ERR 	-1
#define LOOP_ERR 		-2



// CONSTANTS

#define MAC_SIZE 		6
#define CHARS_PER_LINE  32
#define CHARS_PER_BLOCK 8




// STRUCTS

typedef struct pkt {
	//meta
	int order;
	const u_char *start; 		// pointer to the start of frame

	// link layer
	int len;
	int real_len;

	uint8_t		*dst_mac;
	uint8_t 	*src_mac;
	uint8_t		*log_header;
	uint16_t 	eth_type;
	uint8_t 	ssap;


	char *eth_type_name;
} pkt;

typedef struct ip_header {
	uint8_t *ip_header_start;
	uint8_t *ttl;
	uint8_t *protocol;
	uint32_t *src_addr;
	uint32_t *dst_addr;
} ip_header;

typedef struct node {
	uint32_t node_ip;
	unsigned int nreceived;
	struct node *next;
} node;

typedef struct ipv4_stats {
	uint32_t ip;
	unsigned int count;
} ipv4_stats;

typedef struct protocol {
	int n;
	int nstop;
	char *name;
} protocol;




// UTILITY FUNCTIONS FOR PCAP SHARK

pcap_t *open_capfile 	(char *filename);
void 	print_pkt 		(pkt *pkt);
void 	hexdump 		(uint8_t *data, unsigned int n);
void 	print_mac 		(uint8_t *start);
void 	print_eth_name 	(pkt *pkt);

void 	print_trans_protocol (pkt *pkt);

protocol *load_protocols	(char *srcfile);
void 	  free_protocols 	(protocol *protocols);

void 	parse_link_layer 	(pkt *pkt);
void 	parse_ieee_snap 	(pkt *pkt);
void parse_ethii (pkt *pkt, ipv4_stats *src_ips, ipv4_stats *dst_ips, unsigned int *src_ips_count, unsigned int *dst_ips_count);


void print_ipv4_stats();

void print_802_3_subprotocol (protocol *protocols, uint8_t LSAP);
void print_ipv4_subprotocol (protocol *protocols, uint8_t n);
void print_tcp_protocol(protocol *protocols, uint16_t port);
void print_udp_protocol(protocol *protocols, uint16_t port);
