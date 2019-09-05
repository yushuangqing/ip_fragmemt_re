#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  
#include <sys/types.h>  
#include <dirent.h>  
#include <sys/stat.h>  
#include <pwd.h>  
#include <grp.h>  
#include <unistd.h>  
#include <string.h>  
#include <getopt.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <termios.h>
#include <time.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include "list.h"
#include <endian.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#define LINE_LEN 16
#define IP_HEAD 20
#define MAC_HEAD 14
#define FLAGS1_1 20
#define FLAGS1_2 21
#define IDENTIFICATION_1 18
#define IDENTIFICATION_2 19

int is_autogetpacke = 0;
int mtu = 1500;
int fragment_length = 0;      //分片之后长度
int fragment_filter_length = 0;
int reassemble_length = 0 ;  //重组之后长度；
pcap_t *file_fragment = NULL;
pcap_t *file_reassemble = NULL;
pcap_t *source_pcap_fragment=NULL;
pcap_dumper_t *pdumper_fragment = NULL;
pcap_dumper_t *pdumper_reassembled = NULL;
pcap_t *source_pcap_reassembled = NULL;
int fragment_filter_packet = 0;
int auto_get_packet_size = 500;








//MyList *list=NULL;
MyList *list_reassembled=NULL;

typedef struct node
{
	struct pcap_pkthdr *hdr;
	u_char *data;
}Packet;

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



u_short merge_two_u_char(u_char *data)
{

	u_short *p = (u_short *)data;
	u_short temp = *p;
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
		temp = htons(temp);
	return temp;
}

u_short checknum(u_char *data, int length)
{

	u_int sum =0;
	for(int i=0; i < length ;i += 2)
	{
		u_short p = merge_two_u_char(&data[i]);

		sum += (u_int)p;
	}

	u_short  d = (u_short)sum;
	u_short  f = (u_short)(sum>>16);
	u_short s =(u_short)(d + f);

	return  ~s;
}





void write_packet(pcap_dumper_t *pdumper, Packet *packet)
{
	pcap_dump((u_char*)pdumper, packet->hdr, packet->data);
}



void free_data(void *data)
{
	Packet *packet = (Packet *)data;
	free(packet->hdr);
	free(packet->data);
	free(packet);
}

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


void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if(is_autogetpacke == 1)
	{
		printf("get a packet with length of [%d]\n",header->len);
		if( header->len <= (mtu + MAC_HEAD) )
		{
			fragment_filter_packet++;

			return ;
		}
	
		const u_char *ip_head_data = pkt_data + MAC_HEAD;
		struct ip *ip_head_s = (struct ip *)ip_head_data;
		u_short ip_off;
		if (__BYTE_ORDER == __LITTLE_ENDIAN)
		{
			ip_off =htons(ip_head_s->ip_off);
		}
		else
		{
			ip_off = ip_head_s->ip_off;
		}
		u_short can_fragment = ip_off & IP_DF;
		u_short more_fragment = ip_off & IP_MF;
		u_short initoffset = ip_off & IP_OFFMASK;
		unsigned int ip_v = ip_head_s->ip_v;
		


		if(!((can_fragment == 0) 
					&& (initoffset == 0)
					&& (more_fragment == 0)  
					&& (ip_v == 4)))
		{
			fragment_filter_packet++;
			return ;
		}

	}

	if((mtu - IP_HEAD)%8 != 0)
		mtu = mtu - (mtu - IP_HEAD)%8;

	int num_ip_fragment = (header->len - MAC_HEAD - IP_HEAD - 1 )/(mtu - IP_HEAD) + 1;
	fragment_length += num_ip_fragment;
	//	printf("num_ip_fragment = %d\n", num_ip_fragment);



	const u_char *pdata =pkt_data + MAC_HEAD + IP_HEAD; 
	for(int i=1;i<=num_ip_fragment;i++)
	{
		Packet *packet = NULL;	
		packet = (Packet *)malloc(sizeof(Packet));
		if(packet == NULL)
			return ;
		if(i != num_ip_fragment)
		{
			packet->data = NULL;
			packet->data = (u_char *) malloc (sizeof(u_char) *(MAC_HEAD + mtu) + 1);
			if(packet->data == NULL)
			{
				free(packet);
				return;
			}
			packet->hdr = NULL;
			packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
			if(packet->hdr == NULL)
			{
				free(packet->data);
				free(packet);
				return ;
			}
			packet->hdr->len = mtu + MAC_HEAD;
			packet->hdr->caplen =  mtu + MAC_HEAD;
			packet->hdr->ts.tv_sec = header->ts.tv_sec;
			packet->hdr->ts.tv_usec = header->ts.tv_usec;

			int j;
			int index= 0 ;

			for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
				packet->data[index++] = pkt_data[j];






			/*
			   u_char *flength = packet->data + 14 + 2;
			   u_short packet_length = (u_short) mtu;
			   flength[1] = (u_char)(packet_length);
			   flength[0] = (u_short)(packet_length>>8);






			   u_char *foffset= packet->data + 14 + 6;
			   u_short offset = (i-1)*(mtu-IP_HEAD)/8;
			   foffset[1] = (u_char)offset;
			   foffset[0] = (u_char)(offset>>8);
			   foffset[0]|= (0x20);

			   u_char *check = packet->data + 14 + 10;
			   check[0] = 0x00;
			   check[1] = 0x00;
			   u_short finalchecknum = checknum(packet->data + 14, 20);
			   check[1]= ~((u_short)finalchecknum);
			   check[0] = ~((u_short)(finalchecknum>>8));
			 */



			u_char *ip_head_data = packet->data + MAC_HEAD;
			struct ip *ip_head_s = (struct ip *)ip_head_data;
			u_short packet_length = (u_short)mtu;
			u_short offset = (i-1)*(mtu-IP_HEAD)>>3;
			offset = offset | 0x2000 ;

			if (__BYTE_ORDER == __LITTLE_ENDIAN)
			{
				ip_head_s->ip_len = htons(packet_length);
				ip_head_s->ip_off = htons(offset);
				ip_head_s->ip_sum = 0x0000;
				u_short finalchecknum = checknum(ip_head_data, 20);
				ip_head_s->ip_sum = htons(finalchecknum);
			}
			else
			{
				ip_head_s->ip_len = packet_length;
				ip_head_s->ip_off = offset;
				ip_head_s->ip_sum = 0x0000;
				u_short finalchecknum = checknum(ip_head_data, 20);
				ip_head_s->ip_sum = finalchecknum;
			}


			for (j = (i-1)*(mtu-IP_HEAD); j <i*(mtu - IP_HEAD); j++ )
				packet->data[index++] = pdata[j];
			packet->data[index]='\0';


			write_packet(pdumper_fragment,packet);
			free_data(packet);	
		}

		else 
		{
			packet->data = NULL;
			packet->data = (u_char *)malloc(header->len - (mtu - IP_HEAD)*(num_ip_fragment -1) + 1);
			if(packet->data == NULL)
			{
				free(packet);
				return;
			}
			packet->hdr = NULL;
			packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
			if(packet->hdr == NULL)
			{
				free(packet->data);
				free(packet);
				return ;
			}

			packet->hdr->len = header->len - (mtu - IP_HEAD)*(num_ip_fragment - 1 );

			packet->hdr->caplen =  packet->hdr->len;
			packet->hdr->ts.tv_sec = header->ts.tv_sec;
			packet->hdr->ts.tv_usec = header->ts.tv_usec;

			int j;
			int index= 0 ;

			for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
				packet->data[index++] = pkt_data[j];

			/*
			   u_char *flength = packet->data + 14 + 2;
			   u_short packet_length = (u_short)(packet->hdr->len - MAC_HEAD);
			   flength[1] = (u_char)(packet_length);
			   flength[0] = (u_short)(packet_length>>8);

			   u_char *foffset= packet->data + 14 + 6;
			   u_short offset = (i-1)*(mtu-IP_HEAD)/8;
			   foffset[1] = (u_char)offset;
			   foffset[0] = (u_char)(offset>>8);


			   u_char *check = packet->data + 14 + 10;
			   check[0] = 0x00;
			   check[1] = 0x00;
			   u_short finalchecknum = checknum(packet->data + 14, 20);
			   check[1]= ~((u_short)finalchecknum);
			   check[0] = ~((u_short)(finalchecknum>>8));

			 */



			u_char *ip_head_data = packet->data + MAC_HEAD;
			struct ip *ip_head_s = (struct ip *)ip_head_data;
			u_short packet_length = (u_short)(packet->hdr->len - MAC_HEAD);
			u_short offset = (i-1)*(mtu-IP_HEAD)>>3;

			if (__BYTE_ORDER == __LITTLE_ENDIAN)
			{
				ip_head_s->ip_len = htons(packet_length);
				ip_head_s->ip_off = htons(offset);
				ip_head_s->ip_sum = 0x0000;
				u_short finalchecknum = checknum(ip_head_data, 20);
				ip_head_s->ip_sum = htons(finalchecknum);
			}
			else
			{
				ip_head_s->ip_len = packet_length;
				ip_head_s->ip_off = offset;
				ip_head_s->ip_sum = 0x0000;
				u_short finalchecknum = checknum(ip_head_data, 20);
				ip_head_s->ip_sum = finalchecknum;
			}


			for (j = (num_ip_fragment - 1)*(mtu-IP_HEAD); j < header->len - MAC_HEAD - IP_HEAD; j++ )
				packet->data[index++] = pdata[j];

			packet->data[index]='\0';

			write_packet(pdumper_fragment,packet);	
			free_data(packet);	

		}
	}


}

void print_pcap(char *file)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	//打开pcap文件
	if ((file_fragment = pcap_open_offline(file,	   // name of the device
					errbuf					                    // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", file);
		return ;
	}
	pcap_loop(file_fragment, 0, dispatcher_handler, NULL);
	pcap_close(file_fragment);

}











void filter_pcap(char *file)
{
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	pcap_t *source_pcap_filter=NULL;
	pcap_dumper_t *pdumper_filter = NULL;

	if( NULL==(source_pcap_filter=pcap_open_offline(file, errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		return ;
	}
	//打开保存的pcap文件	
	if( NULL==(pdumper_filter=pcap_dump_open(source_pcap_filter,"./gl_icmp.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		pcap_close(source_pcap_filter);

		return ;

	}

	//	printf("过滤前还有%d包\n",get_pcap_length(file));
	



	/*	struct bpf_program filter;
		char filter_str[30];
		snprintf(filter_str,sizeof(filter_str),"greater %d  and ip",mtu + MAC_HEAD );
		if( -1==pcap_compile(source_pcap_filter, &filter, filter_str, 1, 0) )
		{
		printf("pcap_compile() fail.\n");
		printf("errno:%s\n", pcap_geterr(source_pcap_filter));
		return ;


		}
		if( -1==pcap_setfilter(source_pcap_filter, &filter) )
		{
		printf("pcap_setfilter() fail.\n");
		pcap_close(source_pcap_filter);
		return ;

		}
	 */



	int before_filter = 0;
	struct pcap_pkthdr *packet;
	const u_char *pktStr;
	int s=pcap_next_ex(source_pcap_filter, &packet, &pktStr);
	int gllength = 0;
	while( s > 0 )
	{
		if( NULL==pktStr )
		{
			printf("pcap_next() return NULL.\n");
			break;		
		}
		else
		{

			before_filter++;
			const u_char *ip_head_data = pktStr + MAC_HEAD;
			struct ip *ip_head_s = (struct ip *)ip_head_data;
			u_short ip_off;
			if (__BYTE_ORDER == __LITTLE_ENDIAN)
			{
				ip_off =htons(ip_head_s->ip_off);
			}
			else
			{
				ip_off = ip_head_s->ip_off;
			}
			u_short can_fragment = ip_off & IP_DF;
			u_short more_fragment = ip_off & IP_MF;
			u_short initoffset = ip_off & IP_OFFMASK;
			unsigned int ip_v = ip_head_s->ip_v;

			/*
			   const u_char *fcan_fragment = pktStr + 14 + 6;
			   u_char can_fragment =(u_char) (fcan_fragment[0]>>5);
			   u_short twovalue = (u_short)(fcan_fragment[0]<<8) + (u_short)fcan_fragment[1]; 
			   u_short initoffset = twovalue & 0x1fff;
			 */


			if((can_fragment == 0) 
					&& (initoffset == 0)
					&& (more_fragment == 0) 
					&& (packet->len > (mtu + MAC_HEAD)) 
					&& (ip_v == 4))
			{
				pcap_dump((u_char*)pdumper_filter, packet, pktStr);	//读到的数据包写入生成pcap文件
				gllength++;
			}

		}		
		s=pcap_next_ex(source_pcap_filter, &packet, &pktStr);
	}
	
	printf("过滤前还有%d包\n",before_filter);
	printf("过滤后还有%d包\n",gllength);


	pcap_close(source_pcap_filter);
	pcap_dump_close(pdumper_filter);





}











void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	pcap_dump(user, pkt_header, pkt_data);// 输出数据到文件
	printf("get a packet with length of [%d]\n", pkt_header->len);// 打印抓到的包的长度
}

void autogetpacket(char *Netport,char *writefile)
{

	pcap_t *handle;                 // 会话句柄 

	char errbuf[PCAP_ERRBUF_SIZE]; // 存储错误信息的字符串

	bpf_u_int32 mask;               //所在网络的掩码 
	bpf_u_int32 net;                // 主机的IP地址 

	//	struct bpf_program filter;      //已经编译好的过滤器
	//	char filter_app[] = "ip";  //BPF过滤规则,和tcpdump使用的是同一种过滤规则

	/* 探查设备及属性 */
	char *dev = Netport;                      //指定需要被抓包的设备 我们在linux下的两个设备eth0和lo分别是网卡和本地环回
	//	dev = pcap_lookupdev(errbuf);   //返回第一个合法的设备，我这里是eth0
	pcap_lookupnet(dev, &net, &mask, errbuf);

	/* 以混杂模式打开会话 */
	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

	/* 编译并应用过滤器 */
	//	pcap_compile(handle, &filter, filter_app, 0, net);
	//	pcap_setfilter(handle, &filter);

	/* 定义输出文件 */
	pcap_dumper_t* out_pcap;


	out_pcap  = pcap_dump_open(handle,"./autogetpacket.pcap");


	/* 截获length个包 */
	//pcap_loop(handle,500,packet_handler,(u_char *)out_pcap);

	//打开保存的pcap文件	
	if( NULL==(pdumper_fragment=pcap_dump_open(handle,writefile)) )
	{
		printf("pcap_dump_open() fail.\n");
		pcap_close(source_pcap_fragment);
		return ;
	}
	pcap_loop(handle,auto_get_packet_size,dispatcher_handler,(u_char *)out_pcap);






	printf("\n自动抓取%d个包\n",auto_get_packet_size);
	printf("过滤后还有%d个包\n", auto_get_packet_size-fragment_filter_packet);
	printf("分片之后有%d包\n",fragment_length);





	/* 刷新缓冲区 */
	pcap_dump_flush(out_pcap);

	/* 关闭资源 */
	pcap_close(handle);
	pcap_dump_close(out_pcap);
	pcap_dump_flush(pdumper_fragment);
	pcap_dump_close(pdumper_fragment);
//	pcap_close(source_pcap_fragment);


}










void fragment_packet(char *filename)
{

	filter_pcap(filename);
	print_pcap("gl_icmp.pcap");	
	//print_pcap(filename);
	//	printf("过滤之后有%d包\n",fragment_filter_length);
	printf("分片之后有%d包\n",fragment_length);

	//	list = createMyList();
	//	write_pcap(pdumper);
	//	if(list->length == 0) 
	//		printf("所有的包都不需要分片\n");
	//	else
	//		printf("\n%d \n", list->length);
	//	freeMyList(list,free_data);


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

	/*
	   u_char *flength = final_packet->data + 14 + 2;
	   u_short packet_length = (u_short)(final_len - MAC_HEAD) ; 
	   flength[1] = (u_char)(packet_length);
	   flength[0] = (u_short)(packet_length>>8);

	   u_char *foffset= final_packet->data + 14 + 6;
	   foffset[0] = 0x00;
	   foffset[1] = 0x00;

	   u_char *check = final_packet->data + 14 + 10;
	   check[0] = 0x00;
	   check[1] = 0x00;
	   u_short finalchecknum = checknum(final_packet->data + 14, 20);
	   check[1]= ~((u_short)finalchecknum);
	   check[0] = ~((u_short)(finalchecknum>>8));
	 */

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

int junge_networkcard(char *str)
{


	int i=0;
	int sockfd;
	struct ifconf ifc;
	char buf[512];
	struct ifreq *ifr;
	//初始化ifconf
	ifc.ifc_len = 512;
	ifc.ifc_buf = buf;

	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)
	{
		perror("socket");
	}  
	ioctl(sockfd, SIOCGIFCONF, &ifc);    //获取所有接口信息

	//接下来获取逐个网卡的名称
	ifr = (struct ifreq*)buf;  
	for(i=(ifc.ifc_len/sizeof(struct ifreq)); i>0; i--)
	{
		//	printf("name = [%s]\n", ifr->ifr_name);
		if(strcmp(ifr->ifr_name,str) == 0)
			return 1;
		ifr++;
	}
	return 0;
}
int main(int argc, char *argv[])
{
	int opt;
	int is_foc = 0;
	char *writefile = "final.pcap";
	char *network = NULL;

	while ((opt = getopt(argc, argv, "m:a:cw:s:")) != -1)
	{
		switch (opt) 
		{
			case 'm':
				mtu=atoi(optarg);
				break;
			case 'a':
				if(junge_networkcard(optarg) == 0)
				{
					printf("%s 不是网卡\n",optarg);
					return 1;
				}
				network = optarg;
				is_autogetpacke = 1;
				break;
			case 'c':
				is_foc = 1;
				break;
			case 'w':
				writefile = optarg;
				break;
			case 's':
				auto_get_packet_size = atoi(optarg);
				break;
			case '?':
				printf("Unknown option: %c\n",(char)optopt);
				break;
			default :
				printf("输入的非法\n");
				break;
		}

	}
	if(is_autogetpacke == 0)
	{
		if(optind != argc)
		{
			if( is_foc == 0)
			{

				char errbuf[PCAP_ERRBUF_SIZE]={0};
				if( NULL==(source_pcap_fragment=pcap_open_offline(argv[optind], errbuf)) )
				{
					printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
					return 1;
				}
				//打开保存的pcap文件	
				if( NULL==(pdumper_fragment=pcap_dump_open(source_pcap_fragment,writefile)) )
				{
					printf("pcap_dump_open() fail.\n");
					pcap_close(source_pcap_fragment);
					return 1;
				}


				for(int i = optind; i < argc ; i++)
				{
					printf("处理%s \n",argv[i]);
					fragment_packet(argv[i]);
					printf("\n");

				}


				pcap_dump_flush(pdumper_fragment);
				pcap_dump_close(pdumper_fragment);
				pcap_close(source_pcap_fragment);
			}
			else
			{
				char errbuf[PCAP_ERRBUF_SIZE]={0};
				if( NULL==(source_pcap_reassembled=pcap_open_offline(argv[optind], errbuf)) )
				{
					printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
					return 1;
				}
				//打开保存的pcap文件	
				if( NULL==(pdumper_reassembled=pcap_dump_open(source_pcap_reassembled,writefile)) )
				{
					printf("pcap_dump_open() fail.\n");
					pcap_close(source_pcap_reassembled);
					return 1;
				}

				for(int i = optind; i < argc ; i++)
				{
					printf("处理%s\n",argv[i]);
					reassembled(argv[i]);
					printf("\n");
				}

				pcap_dump_flush(pdumper_reassembled);
				pcap_dump_close(pdumper_reassembled);
				pcap_close(source_pcap_reassembled);

			}


		}
	}
	else if(is_autogetpacke == 1)
	{

		autogetpacket(network,writefile);
	}
	return 0;

}






