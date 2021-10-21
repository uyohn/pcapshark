// github: https://github.com/uyohn/PcapShark
// V2 - version for Winter Semester 2021/2022
// refactor of code from last year

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/types.h>

#include "pcap-shark.h"



// -----------------------
// GLOBALS

int pkt_order = 1; 	// frame counter
pcap_t *fp; 		// pointer to capfile file

protocol *ethernetII_protocols,
		 *eth802_3_protocols,
		 *ipv4_protocols,
		 *tcp_protocols,
		 *udp_protocols;


// -----------------------
// FUNCTION DEFINITIONS

void packetHandler ();




int main (int argc, char **argv) {

	// --------------------
	// SET-UP

	// open cap file
	if (argv[1] == NULL) {
		printf("Supply a pcap file path!\nExiting...");
		exit(FILE_OPEN_ERR);
	}

	pcap_t *handle = open_capfile(argv[1]);

	if (handle == NULL)
		exit(FILE_OPEN_ERR);

	fp = handle;


	// load protocols from files
	ethernetII_protocols = load_protocols("source/ethernetII_protocols.txt");
	eth802_3_protocols = load_protocols("source/802-3_protocols.txt");
	ipv4_protocols = load_protocols("source/ipv4_protocols.txt");
	tcp_protocols = load_protocols("source/tcp_protocols.txt");
	udp_protocols = load_protocols("source/udp_protocols.txt");



	// --------------------
	// MAIN

	// start packet processing loop
	if (pcap_loop(handle, 0, packetHandler, NULL) < 0) {
		printf("pcap_loop() failed: %s\n", pcap_geterr(handle) );
		exit(LOOP_ERR);
	}



	// --------------------
	// CLEAN UP

	free_protocols(ethernetII_protocols);
	free_protocols(eth802_3_protocols);
	free_protocols(ipv4_protocols);


	return 0;
}

void packetHandler (u_char *serData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

	// TODO: don't alloc memory for each frame one-by-one
	pkt *current = (pkt *) malloc(sizeof(pkt));

	// TODO: maybe cleanup this?
	current->start 		= packet;
	current->order 		= pkt_order++;
	current->len 		= pkthdr->len;

	// parse the frame layer-by-layer
	parse_link_layer(current);


	if ( be16toh(*current->eth_type) >= 1500) {
		// ETH II frame
		parse_ethii(current);


	} else if ( (uint8_t) *current->log_header == 0xFF ) {
		// 802.3 RAW
		*current->eth_type = 0xFF;
		
	} else if ( (uint8_t) *current->log_header == 0xAA ) {
		// 802.3 LLC + SNAP

		// update eth_type to reflect velue from SNAP header
		*current->eth_type = 0xAA;

		parse_ieee_snap(current);
	
	} else {
		// 802.3 LLC

	}

	print_pkt(*current);

	// CLEANUP
	free(current);
}


