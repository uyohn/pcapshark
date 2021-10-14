#include <pcap/pcap.h>
#include <stdint.h>


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
	int len;
	int real_len;

	char *eth_type_name;
	
	// data
	uint8_t		*dst_mac;
	uint8_t 	*src_mac;
	uint16_t 	*eth_type;
	uint16_t	*log_header;
} pkt;



// UTILITY FUNCTIONS FOR PCAP SHARK

pcap_t *open_capfile 	(char *filename);
void 	print_pkt 		(pkt packet);
void 	hexdump 		(uint8_t *data, unsigned int n);
void 	print_mac 		(uint8_t *start);
