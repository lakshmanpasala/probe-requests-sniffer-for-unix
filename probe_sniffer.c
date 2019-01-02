#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "radiotap_iter.h"
#include <signal.h>
#include <string.h>
#include <getopt.h>

int global = 0;
int verbose = 0;

float signalToDistance( int RSSI) {
		// Frequency being taken as 2.5GHz and a constant
		// can be gotten from the packet
		// formula changes to
		// float exp = (27.55-RSSI-(20*log10(frequency)))/(n)*20.00;
		// have set n = 2
		// might change depending on the environment
    float exp = (-(RSSI)-40.09)/40;
    return pow(10, exp);
}

int print_radiotap_header(const u_char *Buffer, int Size){
	struct ieee80211_radiotap_iterator iter;
	void *data = (void*)Buffer;
	int err;
	int offset;
	const u_char *essid; // a place to put our ESSID / from the packet
	const u_char *essidLen;
	essid = data + 64; // store the ESSID/Router name too
	essidLen = data + 63; // store the ESSID length // this can be used to avoid looping bytes until >0x1 as below
	// 87 byte offset contains the "channel number" as per 802.11, e.g. 2412 = "channel 11"
	char *ssid = malloc(63); // 63 byte limit
	unsigned int i = 0; // used in loop below:
	while(essid[i] > 0x1){ // uncomment these to see each byte individually:
		//printf ("hex byte: %x\n",essid[i]); // view byte
		//printf ("hex char: %c\n",essid[i]); // view ASCII
		ssid[i] = essid[i]; // store the ESSID bytes in *ssid
		i++; // POSTFIX
	}
	ssid[i] = '\0'; // terminate the string
	err = ieee80211_radiotap_iterator_init(&iter, data, Size, NULL);
	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return -3;
	}
	offset = iter._max_length;
	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
			printf("RSSI = %idBm", (int)iter.this_arg[0] - 256);
			printf("\n");
			printf("DISTANCE = %.02fm",  signalToDistance((int)iter.this_arg[0] - 256));
			printf("\n");
			//FIX ME
			//ssid not being parsed correctly
			printf("SSID = %s", ssid);
			printf("\n");
		}
	}

	if (err != -ENOENT) {
		printf("malformed radiotap data\n");
		return -3;
	}

	return offset;
}

void print_ethernet_header(const u_char *Buffer, int Size){
	const u_char *source_mac_addr;
	const u_char *destination_mac_addr;
	destination_mac_addr = Buffer + 4;
	source_mac_addr = Buffer + 10;
	fprintf(stdout,"MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",source_mac_addr[0],source_mac_addr[1],source_mac_addr[2],source_mac_addr[3],source_mac_addr[4],source_mac_addr[5]);
}

void my_callback(u_char *args, const struct pcap_pkthdr* header, const u_char* packet)
{
	int offset;
	int size = header->len;
	offset = print_radiotap_header(packet, size);
	if(offset > 0)
		print_ethernet_header(packet + offset, size);
	global++;
	fprintf(stdout,"/*-----------------------------------Pkt #%i-----------------------------------*/\n", global);
	fflush(stdout);

}


int main(int argc,char **argv)
{
	printf("Start\n");
	fflush(stdout);
	int i;
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	char filter_exp[] = "type mgt subtype probe-req";	/* The filter expression */
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;    /* net/ethernet.h */
	struct bpf_program fp;        /* hold compiled program */
	bpf_u_int32 maskp;            /* subnet mask */
	bpf_u_int32 netp;             /* ip */
	int option_index = 0;

	static const struct option long_options[] = {
			{ "verbose",	no_argument,	NULL, 'v' },
			{ "interface",	required_argument,	NULL, 'i' }
	};

	do {
		option_index = getopt_long(argc, argv, "hvi:m:p", long_options, &option_index);
		switch (option_index)
				{
				case 'v':
						verbose++;
						break;

				case 'i':
						dev = optarg;
						break;

				default:
				break;
				}
		} while (option_index != -1);
	/* Now get a device */
	//dev = pcap_lookupdev(errbuf);
	//dev = "wlp2s0mon";
	printf("Interface: %s\n", dev);

	if(dev == NULL) {
		printf("Missing interface! Add it using -i [interface]\n");
		exit(1);
	}
	/* Get the network address and mask */
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	/* open device for reading in promiscuous mode */
	descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(descr == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}
	/* Check if the network interface provides the radiotap header */
	if (pcap_datalink(descr) != DLT_IEEE802_11_RADIO) {
		fprintf(stderr, "Device %s doesn't provide 802.11 radiotap header - not supported\n", dev);
		return(2);
	}

    	/* Compile and apply the filter */
	if (pcap_compile(descr, &fp, filter_exp, 0, netp) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
		return(2);
	}
	if (pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
		return(2);
	}

	/* loop for callback function */
	pcap_loop(descr, -1, my_callback, NULL);
	return 0;
}
