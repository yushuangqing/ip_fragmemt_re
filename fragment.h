#ifndef FRAGMENT_H
#define FRAGMENT_H

#include <pcap.h>
#include <stdlib.h>
#include <sys/types.h>  


typedef struct node
{
	struct pcap_pkthdr *hdr;
	u_char *data;
}Packet;

void fragment_packet(char *filename);
void filter_pcap(char *file);
void print_pcap(char *file);
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
void write_packet(pcap_dumper_t *pdumper, Packet *packet);
void free_data(void *data);
u_short checknum(u_char *data, int length);
u_short merge_two_u_char(u_char *data);

#endif