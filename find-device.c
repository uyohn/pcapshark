#include <pcap/pcap.h>
#include <stdio.h>

int main () {
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
		printf("%2d. %s", i++, device->name);
		if (device->description)
			printf(" - %s", device->description);

		printf("\n");
	}

	if (i == 1) {
		printf("\nNo interfaces found!\n");
		return 0;
	}

	// Free the device list
	pcap_freealldevs(alldevs);
	return (0);
}
