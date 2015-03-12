#include "pirni.h"
#include <netinet/ip.h>
#include <netinet/if_ether.h> 

int packetsCaptured = 0;

/**********************************************
 * processPacket() -
 * 		Processes all packets recieved and
 * 		logs them.
 * *******************************************/
void processPacket(u_char *dumpfile, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
	pcap_dump(dumpfile, pkthdr, packet);
	
	printf("\r[*] Packets captured: %d", packetsCaptured++);
	fflush(stdout);
	
	return;
}

void initSniffer(char *bpf_filter, char *dump_path)
{
	bpf_u_int32			netaddr = 0, mask = 0;		// To store network address and netmask
	struct bpf_program	filter;						// To store the BPF filter program
	pcap_t				*descr = NULL;				// Network interface handler
	char				errbuf[PCAP_ERRBUF_SIZE];	// Error buffer
	char				*filterargv = bpf_filter;	// Filter supplied by end user
	//int					packetsCaptured = 0;
	
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	printf("[+] Opening device %s\n", device);
	
	/* Open device in promiscious mode (non-working for iPhone, but we still have to do this) */
	descr = pcap_open_live(device, MAXBYTES2CAPTURE, 0, 512, errbuf);
	if(descr == NULL)
	{
		printf("[-] Couldn't open device %s: %s\n", device, errbuf);
		return;
	}
	
	/* Look up info from the capture device */
	if(pcap_lookupnet(device, &netaddr, &mask, errbuf) == -1) {
		printf("[-] Couldn't look up IPv4 network number and netmask for %s\n", device);
		return;
	}
		
	/* Compile filter expression into a BPF filter program */
	if(pcap_compile(descr, &filter, filterargv, 1, mask) == -1) {
		printf("[-] Couldn't parse filter\n");
		return;
	}

	/* Load the filter */
	if(pcap_setfilter(descr, &filter) == -1) {
		printf("[-] Couldn't install filter - Typo?. See userguide\n");
		return;
	}
	
	printf("[+] Setting filter: %s\n", filterargv);
	
	dumpfile = pcap_dump_open(descr, dump_path);
	if(dumpfile ==NULL)
	{
		printf("[-] Could not open dump file (check permissions?)\n");
		return;
	}
	
	printf("[*] Collecting packets to %s, use Ctrl-C to cancel (swipe up-right in mobileterminal)\n", dump_path);
	
	/* Loop forever & call processPacket() for every received packet */
	pcap_loop(descr, -1, processPacket, (u_char *)dumpfile);
	
	return;
}
