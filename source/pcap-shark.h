

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
	uint16_t 	*eth_type;


	char *eth_type_name;
} pkt;


typedef struct protocol {
	int n;
	int nstop;
	char *name;
} protocol;




// UTILITY FUNCTIONS FOR PCAP SHARK

pcap_t *open_capfile 	(char *filename);
void 	print_pkt 		(pkt packet);
void 	hexdump 		(uint8_t *data, unsigned int n);
void 	print_mac 		(uint8_t *start);
void 	print_eth_name 	(pkt pkt);

protocol *load_protocols	(char *srcfile);
void 	  free_protocols 	(protocol *protocols);

void 	parse_link_layer 	(pkt *pkt);
void 	parse_ieee_snap 	(pkt *pkt);
void 	parse_ethii 		(pkt *pkt);
