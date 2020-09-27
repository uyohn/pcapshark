#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

int main () {
	// Buffer
	char buffer[65];

	// Struct (linked list)
	pcap_if_t *alldevs;
	pcap_if_t *device;

	// Error buffer
	char errbuf[PCAP_ERRBUF_SIZE];

	// Retrieve the device list from local machine
	if ( pcap_findalldevs(&alldevs, errbuf) == -1 ) {
		printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
		return 1;
	}

	// Print the list
	int i = 1;
	for (device = alldevs; device != NULL; device = device->next) {
		char ip[13];
		char subnet_mask[13];
		bpf_u_int32 ip_raw;
		bpf_u_int32 subnet_mask_raw;
		int lookup_return_code;
		struct in_addr address;

		printf("%2d. %s", i++, device->name);
		if (device->description)
			printf(" - %s", device->description);

		lookup_return_code = pcap_lookupnet(
			device->name,
			&ip_raw,
			&subnet_mask_raw,
			errbuf
		);

		if (lookup_return_code == -1) {
			printf("%s\n", errbuf);
		}

		// Get IP in human-readable form
		address.s_addr = ip_raw;
		strcpy(ip, inet_ntoa(address));
		if (ip == NULL) {
			perror("inet_ntoa");
			return 1;
		}

		address.s_addr = subnet_mask_raw;
		strcpy(subnet_mask, inet_ntoa(address));
		if (subnet_mask == NULL) {
			perror("inet_ntoa");
			return 1;
		}

		printf("\n");

		printf("IP address: %s\n", ip);
		printf("Subnet mask: %s\n", subnet_mask);

		printf("\n");

		printf("loopback: %d\n", device->flags & PCAP_IF_LOOPBACK);
		printf("up: %d\n", device->flags & PCAP_IF_UP);
		printf("running: %d\n", device->flags & PCAP_IF_RUNNING);
		printf("wireless: %d\n", device->flags & PCAP_IF_WIRELESS);

		printf("\n\n");
	}

	if (i == 1) {
		printf("\nNo interfaces found!\n");
		return 0;
	}

	// Free the device list
	pcap_freealldevs(alldevs);
	return (0);
}
