#ifndef REASSEMBLED_H
#define REASSEMBLED_H


#include "list.h"  //因为要用到    MyList   
#include "fragment.h"//因为要用到   Packet


#include <pcap.h>
#include <stdlib.h>
#include <sys/types.h>  

typedef struct node_reassembled
{
	Packet *packet_head_data;
	int not_fragment;
	int more_fragment;
	int offset;
}Packet_reassembled;

typedef struct node_id
{
	MyList *list_packet;
	u_char identification_1;
	u_char identification_2;
	unsigned int src_ip;
	unsigned int dst_ip;
}All_fragment;

int get_pcap_length(char *filename);
int packet_len(MyList *list);
void reassembled_packet(MyList *list);
int two_char_to_int(unsigned char a, unsigned char b);
int four_char_to_int(unsigned char a, unsigned char b, unsigned char c, unsigned char d);
int cmp_id_ip(void * p, u_char id1, u_char id2, int src_ip, int dst_ip);
MyList* get_list(void * p);
int cmp_offset(void * p1, void * p2);
int if_first_last_fragment(void * p1, void * p2);
int if_near_fragent(void * p1, void * p2);
void free_data_2(void *data);
void free_data_1(void *data);
void copy_id_info(const struct pcap_pkthdr *header, const u_char *pkt_data);
void copy_packet_info(MyList *list, const struct pcap_pkthdr *header, const u_char *pkt_data);
int judge_collected_fragments(MyList *list);
void handle_packet(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
void if_reassembled(char *file);
void reassembled(char *czfilename);

#endif


