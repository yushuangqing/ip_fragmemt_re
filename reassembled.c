#include "reassembled.h"

#include <arpa/inet.h>
#include <dirent.h> 
#include <endian.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <pcap.h>
#include <pwd.h>  
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  
#include <sys/types.h>  
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>  
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>  
#include <unistd.h>

#define IP_HEAD 20
#define MAC_HEAD 14
#define FLAGS1_1 20
#define FLAGS1_2 21
#define IDENTIFICATION_1 18
#define IDENTIFICATION_2 19

//引用外部的全局变量的声明
extern int fragment_length;      //分片之后长度
extern int fragment_filter_length ;
extern int reassemble_length  ;  //重组之后长度；
extern int fragment_filter_packet ;

extern pcap_t *file_fragment ;
extern pcap_t *file_reassemble ;
extern pcap_t *source_pcap_fragment;
extern pcap_t *source_pcap_reassembled ;
extern pcap_dumper_t *pdumper_fragment ;
extern pcap_dumper_t *pdumper_reassembled ;

extern int is_foc ;//定义是分片或重组：      -c的标记，无参数
extern int is_autogetpacke ;//定义自动从网口抓包      -a的标记
extern char *writefile ;//初始化写入的文件名        -w的参数
extern int write_pcap_flag;        //-w 的标记
extern char *network ;//定义网络接口名                         -a的参数
extern int auto_get_packet_size ;//默认抓包数量为500                  -s的参数
extern int mtu;//默认mtu为1500 

extern MyList *list_reassembled;

int get_pcap_length(char *filename)
{
	struct pcap_pkthdr *packet = NULL;
	const u_char *pktStr = NULL;
	pcap_t *source_pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	if( NULL==(source_pcap=pcap_open_offline(filename, errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		return 0;
	}

	int temp = pcap_next_ex(source_pcap, &packet, &pktStr);
	int length = 0;
	while( temp > 0 )
	{		
		length++;	
		temp = pcap_next_ex(source_pcap, &packet, &pktStr);
	}
	pcap_close(source_pcap);
	return length;
}


int packet_len(MyList *list)
{
	int len = 0;
	MyNode * p = list->first;
	while(p != NULL)
	{
		len += ((Packet_reassembled *)p->data)->packet_head_data->hdr->len;
		p = p->next;


	}

	int final_len = len - (list->length-1) * 34;
	return final_len;
}


void reassembled_packet(MyList *list)
{
	Packet *final_packet = NULL;
	final_packet =	(Packet *)malloc(sizeof(Packet));
	if(final_packet == NULL)
		return ;
	int final_len = packet_len(list);

	final_packet->data = NULL;
	final_packet->data = (u_char *) malloc (sizeof(u_char)*(final_len + 1));
	if(final_packet->data == NULL)
	{
		free(final_packet);
		return ;
	}
	final_packet->hdr = NULL;
	final_packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	if(final_packet->hdr == NULL)
	{
		free(final_packet->data);
		free(final_packet);
		return ;
	}

	MyNode * p = list->first;

	final_packet->hdr->len = final_len;
	final_packet->hdr->caplen = final_len;

	final_packet->hdr->ts.tv_sec = ((Packet_reassembled *)p->data)->packet_head_data->hdr->ts.tv_sec;
	final_packet->hdr->ts.tv_usec = ((Packet_reassembled *)p->data)->packet_head_data->hdr->ts.tv_usec;

	int j;
	int index = 0 ;

	for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
		final_packet->data[index++] = ((Packet_reassembled *)p->data)->packet_head_data->data[j];

	u_char *ip_head_data = final_packet->data + MAC_HEAD;
	struct ip *ip_head_s = (struct ip *)ip_head_data;
	ip_head_s->ip_off = 0x0000;
	u_short packet_length = (u_short)(final_len - MAC_HEAD) ; 

	if (__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		ip_head_s->ip_len = htons(packet_length);
		ip_head_s->ip_sum = 0x0000;
		u_short finalchecknum = checknum(ip_head_data, 20);
		ip_head_s->ip_sum = htons(finalchecknum);
	}
	else
	{
		ip_head_s->ip_len = packet_length;
		ip_head_s->ip_sum = 0x0000;
		u_short finalchecknum = checknum(ip_head_data, 20);
		ip_head_s->ip_sum = finalchecknum;
	}

	while(p != NULL)
	{
		Packet_reassembled *pckr = (Packet_reassembled *)p->data;
		Packet *packet = pckr->packet_head_data;

		int len = packet->hdr->caplen;
		for(int i = MAC_HEAD + IP_HEAD;i <len ;i++)
		{
			final_packet->data[index++] = packet->data[i];
		}
		p = p->next;
	}
	final_packet->data[index] = '\0';

	write_packet(pdumper_reassembled, final_packet);
	reassemble_length++;

	free_data(final_packet);
}


int two_char_to_int(unsigned char a, unsigned char b)
{
	return ((a<<8) | b) & 0x1fff;
}


int four_char_to_int(unsigned char a, unsigned char b, unsigned char c, unsigned char d)
{
	return (a<<24) | (b<<16) | (c<<8) | d;
}


int cmp_id_ip(void * p, u_char id1, u_char id2, int src_ip, int dst_ip)
{
	All_fragment * pp = p;

	if(pp->identification_1 == id1 && pp->identification_2 == id2 && pp->src_ip == src_ip && pp->dst_ip == dst_ip)
		return 1;
	else
		return 0;
}

MyList* get_list(void * p)
{
	All_fragment * pp = p;
	return pp->list_packet;
}

int cmp_offset(void * p1, void * p2)
{
	Packet_reassembled * pp1 = p1;
	Packet_reassembled * pp2 = p2;
	if(pp1->offset > pp2->offset)
		return 2;
	else if(pp1->offset == pp2->offset)
		return 0;
	else
		return 1;
}

int if_first_last_fragment(void * p1, void * p2)
{

	Packet_reassembled * pp1 = p1;
	Packet_reassembled * pp2 = p2;

	if(pp1->more_fragment == 1 && pp1->offset == 0 && pp2->more_fragment == 0)
	{
		return 1;
	}

	else
	{
		return 0;
	}	
}


int if_near_fragent(void * p1, void * p2)
{
	Packet_reassembled * pp1 = p1;
	Packet_reassembled * pp2 = p2;
	if(pp1->more_fragment == 1 && (8*(pp2->offset - pp1->offset)+IP_HEAD+MAC_HEAD) == pp1->packet_head_data->hdr->len)
	{
		//	printf("为相邻节点\n");
		return 1;
	}
	else
		return 0;
}

void free_data_2(void *data)
{
	Packet_reassembled * pp = (Packet_reassembled *)data;
	free(pp->packet_head_data->hdr); free(pp->packet_head_data->data);//释放内层链表每个节点数据中data申请的空间
	free(pp->packet_head_data);//释放内层链表每个节点数据中packet_head_data申请的空间
	free(pp);//释放内层链表每个节点数据申请的空间
}

void free_data_1(void *data)
{
	All_fragment * pp = (All_fragment *)data;

	MyNode *s = NULL;
	while (pp->list_packet->first)
	{
		s = pp->list_packet->first->next;
		free_data_2(pp->list_packet->first->data);//释放内层链表每个节点数据申请的空间
		free(pp->list_packet->first);//释放内层链表每个节点申请的空间
		pp->list_packet->first = s;
	}
	free(pp->list_packet);//释放内层链表
	free(pp);//释放内层链表作为外层链表节点的数据申请的空间
}




void copy_id_info(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if(((pkt_data[FLAGS1_1]>>5) & 1) == 0 && two_char_to_int(pkt_data[FLAGS1_1], pkt_data[FLAGS1_2]) == 0)
		return;

	All_fragment *all_fragment = (All_fragment *)malloc(sizeof(All_fragment));
	if(all_fragment == NULL)
	{
		perror("malloc All_fragment");
		return;
	}

	all_fragment->list_packet = createMyList();

	Packet_reassembled *packet_reassembled = (Packet_reassembled *)malloc(sizeof(Packet_reassembled));
	if(packet_reassembled == NULL)
	{
		free(all_fragment);
		perror("malloc packet_reassembled");
		return;
	}

	packet_reassembled->packet_head_data = (Packet *)malloc(sizeof(Packet));
	if(packet_reassembled->packet_head_data == NULL)
	{
		free(packet_reassembled);
		free(all_fragment);
		perror("malloc packet_reassembled->packet_head_data");
		return;
	}

	packet_reassembled->packet_head_data->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	if(packet_reassembled->packet_head_data->hdr == NULL)
	{
		free(packet_reassembled->packet_head_data);
		free(packet_reassembled);
		free(all_fragment);
		perror("malloc packet_reassembled->packet_head_data->hdr");
		return;
	}

	packet_reassembled->packet_head_data->data = (u_char *)malloc(sizeof(u_char)*(header->len));
	if(packet_reassembled->packet_head_data->data == NULL)
	{
		free(packet_reassembled->packet_head_data->hdr);
		free(packet_reassembled->packet_head_data);
		free(packet_reassembled);
		free(all_fragment);
		perror("malloc packet_reassembled->packet_head_data->data");
		return;
	}

	//id+src_ip+dst_ip
	all_fragment->identification_1 = pkt_data[IDENTIFICATION_1];
	all_fragment->identification_2 = pkt_data[IDENTIFICATION_2];
	all_fragment->src_ip = four_char_to_int(pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29]);
	all_fragment->dst_ip = four_char_to_int(pkt_data[30], pkt_data[31], pkt_data[32], pkt_data[33]);

	//包头
	packet_reassembled->packet_head_data->hdr->len = header->len;
	packet_reassembled->packet_head_data->hdr->caplen = header->caplen;
	packet_reassembled->packet_head_data->hdr->ts.tv_sec = header->ts.tv_sec;
	packet_reassembled->packet_head_data->hdr->ts.tv_usec = header->ts.tv_usec;
	//包数据
	for (int i=0; i<packet_reassembled->packet_head_data->hdr->len; i++)
		packet_reassembled->packet_head_data->data[i] = pkt_data[i]; 

	//MF+DF+偏移量
	packet_reassembled->not_fragment = pkt_data[FLAGS1_1]>>6;
	packet_reassembled->more_fragment = (pkt_data[FLAGS1_1]>>5) & 1;
	packet_reassembled->offset = two_char_to_int(pkt_data[FLAGS1_1], pkt_data[FLAGS1_2]);
	
	//插入id链表
	myListInsertDataAtLast(list_reassembled, all_fragment);

	//插入分片链表
	myListInsertDataAtLast(all_fragment->list_packet, packet_reassembled);
}

void copy_packet_info(MyList *list, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	Packet_reassembled *packet_reassembled = (Packet_reassembled *)malloc(sizeof(Packet_reassembled));
	if(packet_reassembled == NULL)
	{
		perror("malloc packet_reassembled");
		return;
	}

	packet_reassembled->packet_head_data = (Packet *)malloc(sizeof(Packet));
	if(packet_reassembled->packet_head_data == NULL)
	{
		free(packet_reassembled);
		perror("malloc packet_reassembled->packet_head_data");
		return;
	}

	packet_reassembled->packet_head_data->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	if(packet_reassembled->packet_head_data->hdr == NULL)
	{
		free(packet_reassembled->packet_head_data);
		free(packet_reassembled);
		perror("malloc packet_reassembled->packet_head_data->hdr ");
		return;
	}

	packet_reassembled->packet_head_data->data = (u_char *)malloc(sizeof(u_char)*(header->len));
	if(packet_reassembled->packet_head_data->data == NULL)
	{
		free(packet_reassembled->packet_head_data->hdr);
		free(packet_reassembled->packet_head_data);
		free(packet_reassembled);
		perror("malloc packet_reassembled->packet_head_data->data");
		return;
	}

	//包头
	packet_reassembled->packet_head_data->hdr->len = header->len;
	packet_reassembled->packet_head_data->hdr->caplen = header->caplen;
	packet_reassembled->packet_head_data->hdr->ts.tv_sec = header->ts.tv_sec;
	packet_reassembled->packet_head_data->hdr->ts.tv_usec = header->ts.tv_usec;
	//包数据
	for (int i=0; i<packet_reassembled->packet_head_data->hdr->len; i++)
		packet_reassembled->packet_head_data->data[i] = pkt_data[i]; 
	//MF+DF+偏移量
	packet_reassembled->not_fragment = pkt_data[FLAGS1_1]>>6;
	packet_reassembled->more_fragment = (pkt_data[FLAGS1_1]>>5) & 1;
	packet_reassembled->offset = two_char_to_int(pkt_data[FLAGS1_1], pkt_data[FLAGS1_2]);


	insert_sort(list, packet_reassembled, cmp_offset, free_data_2);//插入排序
}


//判断是否分片包到齐
int judge_collected_fragments(MyList *list)
{
	//	printf("进入判断是否能重组\n");
	if(if_first_last_fragment(list->first->data, list->last->data))
	{
		MyNode *p = list->first;
		while(p->next)
		{
			if(if_near_fragent(p->data, p->next->data))
			{
				p=p->next;
			}
			else
				return 0;
		}
		return 1;
	}
	else
	{
		return 0;
	}
}

void handle_packet(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	//id链表是否为空
	if(list_reassembled->length == 0)
	{
		copy_id_info(header, pkt_data);
	}
	else
	{
		//id是否存在
		MyNode *p_node= find_info(list_reassembled, pkt_data[IDENTIFICATION_1], pkt_data[IDENTIFICATION_2], four_char_to_int(pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29]), four_char_to_int(pkt_data[30], pkt_data[31], pkt_data[32], pkt_data[33]), cmp_id_ip);
		if(p_node == NULL)//不存在
		{
			copy_id_info(header, pkt_data);
		}
		else//存在
		{	
			copy_packet_info(get_list(p_node->data), header, pkt_data);//
			//判断能否重组
			if( judge_collected_fragments(get_list(p_node->data)) )
			{
				reassembled_packet(get_list(p_node->data));
				delete_node(list_reassembled, p_node, free_data_1);
			}

			else
			{
				return;
			}
		}
	}
}


void if_reassembled(char *file)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((file_reassemble = pcap_open_offline(file,	   // name of the device
					errbuf					                    // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", file);
		return ;
	}

	pcap_loop(file_reassemble, 0, handle_packet, NULL);//捕获并处理所有包（第二个参数为0时），第一个参数为包文件描述符，
	pcap_close(file_reassemble);                           
}


void reassembled(char *czfilename)
{
	printf("重组之前有%d包\n",get_pcap_length(czfilename));
	list_reassembled = createMyList();
	if_reassembled(czfilename);//能否重组

	printf("有%d个包不能重组\n",list_reassembled->length);	
	printf("重组之后有%d包\n",reassemble_length);

	freeMyList(list_reassembled, free_data_1);
}