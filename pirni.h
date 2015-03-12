#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

/* For ARP spoof */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef IP_ALEN
#define IP_ALEN 4
#endif

/* For sniffer */
#define MAXBYTES2CAPTURE	2048
#define ARP_REQUEST			1
#define ARP_REPLY			2

/* HW and IP Adresses */

u_long			SrcIP, DstIP;

/* public variable for libnet handle */
libnet_t	*l;
char		*device;
const char	*outputFile;
pcap_dumper_t	*dumpfile;

		
void LaunchThread();
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet);
void initSniffer();
void sigint_handler(int sig);
