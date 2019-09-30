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
#include <termios.h>
#include <time.h>
#include <pcap/pcap.h>
#include "list.h"
#define LINE_LEN 16

int mtu=500;
pcap_t *fp;
#define IP_HEAD 20
#define MAC_HEAD 14
#define FLAGS1_1 20
#define FLAGS1_2 21
#define IDENTIFICATION_1 18
#define IDENTIFICATION_2 19
typedef struct node_fragment
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
	printf("进入重组首尾判断\n");
	Packet_reassembled * pp1 = p1;
	Packet_reassembled * pp2 = p2;
	printf("pp1->more_fragment=%d\n",pp1->more_fragment);
	printf("pp1->offset=%d\n",pp1->offset);
	printf("pp2->more_fragment=%d\n",pp2->more_fragment);
	if(pp1->more_fragment == 1 && pp1->offset == 0 && pp2->more_fragment == 0)
	{
		printf("首尾判断可以重组\n");
		return 1;
	}
		
	else
	{
		printf("首尾判断不可以重组\n");
		return 0;
		
	}	
}
int if_near_fragent(void * p1, void * p2)
{
	Packet_reassembled * pp1 = p1;
	Packet_reassembled * pp2 = p2;
	if(pp1->more_fragment == 1 && (8*(pp2->offset - pp1->offset)+IP_HEAD+MAC_HEAD) == pp1->packet_head_data->hdr->len)
	{
		printf("为相邻节点\n");
		return 1;
	}
	else
		return 0;
}
void free_data(void *data)
{
	Packet *packet = (Packet *)data;
	free(packet->hdr);
	free(packet->data);
}

void free_data_2(void *data)
{
	Packet_reassembled * pp = (Packet_reassembled *)data;
	free(pp->packet_head_data->hdr);
	free(pp->packet_head_data->data);
	free(pp->packet_head_data);
}

void free_data_1(void *data)
{
	All_fragment * pp = (All_fragment *)data;
	
	MyNode *s = NULL;
	while (pp->list_packet->first)
	{
		s = pp->list_packet->first->next;
		free_data_2(pp->list_packet->first->data);
		free(pp->list_packet->first);
		pp->list_packet->first = s;
	}
	free(pp->list_packet);
}



pcap_t *source_pcap_t=NULL;//网卡句柄或者打开文件的描述符
pcap_dumper_t *des_pcap_dumper_t=NULL;//保存文件的描述符

MyList *list=NULL;
MyList *list_reassembled=NULL;

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
		
	int num_ip_fragment = (header->len - MAC_HEAD - IP_HEAD)/(mtu - IP_HEAD) + 1;
	printf("num_ip_fragment = %d\n", num_ip_fragment);

	const u_char *pdata =pkt_data + MAC_HEAD + IP_HEAD; 
		
	for(int i=1;i<=num_ip_fragment;i++)
	{
		Packet *packet = (Packet *)malloc(sizeof(Packet));
		if(i != num_ip_fragment)
		{
			packet->data = (u_char *) malloc (sizeof(u_char) *(MAC_HEAD + mtu) + 1);
			packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
			//添加分片头部信息
			packet->hdr->len = mtu + MAC_HEAD;
			packet->hdr->caplen =  mtu + MAC_HEAD;
			packet->hdr->ts.tv_sec = header->ts.tv_sec;
			packet->hdr->ts.tv_usec = header->ts.tv_usec;
				
			int j;
			int index= 0 ;

			for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
				packet->data[index++] = pkt_data[j];

			u_char *flength = packet->data + 14 + 6;
			flength[0]^= (1<<5);
	
	

			for (j = (i-1)*(mtu-IP_HEAD); j <i*(mtu - IP_HEAD); j++ )
				packet->data[index++] = pdata[j];
			packet->data[index]='\0';

			myListInsertDataAtLast(list, packet); 
		}

		else 
		{
			packet->data = (u_char *)malloc(header->len - (mtu - IP_HEAD)*(num_ip_fragment -1) + 1);
			packet->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

			packet->hdr->len = header->len - (mtu - IP_HEAD)*(num_ip_fragment - 1 );

			printf ("end   length  %d  \n", packet -> hdr ->len );
			packet->hdr->caplen =  packet->hdr->len;
			packet->hdr->ts.tv_sec = header->ts.tv_sec;
			packet->hdr->ts.tv_usec = header->ts.tv_usec;

			int j;
			int index= 0 ;

			for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
				packet->data[index++] = pkt_data[j];

			u_char *flength = packet->data + 14 + 7;
			flength[0]^= (0<<5);

			for (j = (num_ip_fragment - 1)*(mtu-IP_HEAD); j < header->len - MAC_HEAD - IP_HEAD; j++ )
				packet->data[index++] = pdata[j];

			packet->data[index]='\0';

			myListInsertDataAtLast(list, packet); 
		}
	}
}

void copy_id_info(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	All_fragment *all_fragment = (All_fragment *)malloc(sizeof(All_fragment));
	if(all_fragment == NULL)
	{
		perror("malloc All_fragment");
		return;
	}
	
	all_fragment->list_packet = createMyList();
	
//	if(all_fragment->list_packet == NULL)
//	{
//		perror("malloc all_fragment->list_packet");
//		return;
//	}
	
	Packet_reassembled *packet_reassembled = (Packet_reassembled *)malloc(sizeof(Packet_reassembled));
	if(packet_reassembled == NULL)
	{
		perror("malloc packet_reassembled");
		return;
	}
	
	packet_reassembled->packet_head_data = (Packet *)malloc(sizeof(Packet));
	if(packet_reassembled->packet_head_data == NULL)
	{
		perror("malloc packet_reassembled->packet_head_data");
		return;
	}
	
	packet_reassembled->packet_head_data->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	if(packet_reassembled->packet_head_data->hdr == NULL)
	{
		perror("malloc packet_reassembled->packet_head_data->hdr");
		return;
	}
	
	packet_reassembled->packet_head_data->data = (u_char *)malloc(sizeof(u_char)*((header->len)+1));
	if(packet_reassembled->packet_head_data->data == NULL)
	{
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
	
	
	printf("pkt_data[FLAGS1_1]=%x\n", pkt_data[FLAGS1_1]);
	printf("pkt_data[FLAGS1_2]=%x\n", pkt_data[FLAGS1_2]);
	printf("pkt_data[FLAGS1_1]=%x\n", pkt_data[IDENTIFICATION_1]);
	printf("pkt_data[FLAGS1_2]=%x\n", pkt_data[IDENTIFICATION_2]);
	//MF+DF+偏移量
	packet_reassembled->not_fragment = pkt_data[FLAGS1_1]>>6;
	packet_reassembled->more_fragment = (pkt_data[FLAGS1_1]>>5) & 1;
	packet_reassembled->offset = two_char_to_int(pkt_data[FLAGS1_1], pkt_data[FLAGS1_2]);
	//插入id链表
	
	myListInsertDataAtLast(list_reassembled, all_fragment);
	
	printf("id链表插入成功\n");
	printf("list_reassembled->length=%d\n", list_reassembled->length);
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
		perror("malloc packet_reassembled->packet_head_data");
		return;
	}
	
	packet_reassembled->packet_head_data->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	if(packet_reassembled->packet_head_data->hdr == NULL)
	{
		perror("malloc packet_reassembled->packet_head_data->hdr ");
		return;
	}
	
	packet_reassembled->packet_head_data->data = (u_char *)malloc(sizeof(u_char)*((header->len)+1));
	if(packet_reassembled->packet_head_data->data == NULL)
	{
		perror("malloc packet_reassembled->packet_head_data->data");
		return;
	}
	
	printf("pkt_data[FLAGS1_1]=%x\n", pkt_data[FLAGS1_1]);
	printf("pkt_data[FLAGS1_2]=%x\n", pkt_data[FLAGS1_2]);
	
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
	
	printf("packet_reassembled->not_fragment=%d\n", packet_reassembled->not_fragment);
	printf("packet_reassembled->more_fragment=%d\n", packet_reassembled->more_fragment);
	printf("packet_reassembled->offset=%d\n", packet_reassembled->offset);
	insert_sort(list, packet_reassembled, cmp_offset, free_data_2);//插入排序
}

//判断是否分片包到齐
int judge_collected_fragments(MyList *list)
{
	printf("进入判断是否能重组\n");
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

//重组包的所有长度
int packet_len(MyList *list)
{
	int len = 0;
	//int final_len = 0;
	MyNode * p = list->first;
	while(p != NULL)
	{
		len += (int)(((Packet_reassembled *)p->data)->packet_head_data->hdr->caplen);
		printf("len = %d\n", len);
		p = p->next;
	}
	printf("len=%d\n", len);
	printf("遍历完所有节点长度\n");
	//final_len = len;
	//printf("list->length=%d\n", list->length);
	
	
	//printf("final_len=%d\n", final_len);
	printf("计算出长度\n");
	return 2042;
	//return (int)(len - 34*(list->length-1));
}

//重组
void chongzu(MyList *list)
{
	printf("重组前啊\n");
	Packet_reassembled *final_packet = (Packet_reassembled *)malloc(sizeof(Packet_reassembled));
	
	int final_len = packet_len(list);
	printf("长度获取成功\n");
	//printf("final_len=%d", final_len);
	
	final_packet->packet_head_data->data = (u_char *) malloc (final_len + 1);
	final_packet->packet_head_data->hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	
	printf("头和数据申请成功\n");
	MyNode * p = list->first;

	final_packet->packet_head_data->hdr->len = final_len;
	final_packet->packet_head_data->hdr->caplen = final_len;
	final_packet->packet_head_data->hdr->ts.tv_sec = ((Packet_reassembled *)p->data)->packet_head_data->hdr->ts.tv_sec;
	final_packet->packet_head_data->hdr->ts.tv_usec = ((Packet_reassembled *)p->data)->packet_head_data->hdr->ts.tv_usec;

	int j;
	int index = 0 ;

	for (j = 0; j < MAC_HEAD + IP_HEAD; j++)
		final_packet->packet_head_data->data[index++] = ((Packet_reassembled *)p->data)->packet_head_data->data[j];
	
	while(p != NULL)
	{
	 	Packet_reassembled * packet = (Packet_reassembled *)p->data;
		int len = packet->packet_head_data->hdr->caplen;
		for(int i = MAC_HEAD + IP_HEAD;i <len ;i++)
		{
			final_packet->packet_head_data->data[index++] = packet->packet_head_data->data[i];
		}
		p = p->next;
	}
	final_packet->packet_head_data->data[index] = '\0';
	
	printf("final_len=%d", final_len);
}

//处理每一个分片包
void handle_packet(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	
	printf("\nheader->len=%d\n", header->len);
	
	//id链表是否为空
	if(list_reassembled->length == 0)
	{
		printf("第一条包\n");
		copy_id_info(header, pkt_data);
		printf("第一条包成功插入\n");
	}
	else
	{
		//id是否存在
		MyNode *p_node= find_info(list_reassembled, pkt_data[IDENTIFICATION_1], pkt_data[IDENTIFICATION_2], four_char_to_int(pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29]), four_char_to_int(pkt_data[30], pkt_data[31], pkt_data[32], pkt_data[33]), cmp_id_ip);
		if(p_node == NULL)//不存在
		{
			printf("第4条包\n");
			copy_id_info(header, pkt_data);
		}
		else//存在
		{	
			printf("第2条包\n");
			copy_packet_info(get_list(p_node->data), header, pkt_data);//
			printf("第2条包成功插入\n");
			//判断能否重组
			if( judge_collected_fragments(get_list(p_node->data)) )
			{
				printf("12条包能重组啊\n");
				//chongzu(get_list(p_node->data));
			}
				
			else
			{
				//printf("第12条包不能重组\n");
				return;
			}
				
		}
	}
	
}

void print_pcap(char *file)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	//打开pcap文件
	if ((fp = pcap_open_offline(file,	   // name of the device
					errbuf					                    // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", file);
		return ;
	}
	pcap_loop(fp, 0, dispatcher_handler, NULL);//捕获并处理所有包（第二个参数为0时），第一个参数为包文件描述符，
	pcap_close(fp);                            //第二个参数为函数返回时处理的包的数量，cnt=0表示处理所有数据包，直到产生以下错误之一：读取到EOF；超时读取
												//第三个参数为指定一个带有三个参数的回调函数（第一个参数为pcap_loop传递过来的u_char指针，第二三个为包头和数据）
}                                                 //成功，返回读到的字节数。pcap_dispatch 与pcap_loop功能一样




int exit_main()
{
	printf("exit_main() is called.\n");
	if( NULL!=source_pcap_t )
	{
		pcap_close(source_pcap_t);
	}
	if( NULL!=des_pcap_dumper_t )
	{
		pcap_dump_close(des_pcap_dumper_t);
	}
	exit(0);
}

void filter_pcap(char *file)
{
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	if( NULL==(source_pcap_t=pcap_open_offline(file, errbuf)) )//打开以前保存捕获数据包的文件，用于读取
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		exit_main();
	}
	//打开保存的pcap文件	
	if( NULL==(des_pcap_dumper_t=pcap_dump_open(source_pcap_t,"./gl_icmp.pcap")))//转存数据包，打开用于保存捕获数据包的文件，用于写入
	{                                                                             //source_pcap_t为pcap_open_offline或者pcap_open_live的返回值
		printf("pcap_dump_open() fail.\n");                                        //即网卡句柄
		exit_main();		
	}
	struct bpf_program filter;//定义过滤器
	char filter_str[20];//保存过滤内容
	snprintf(filter_str,sizeof(filter_str),"greater %d",mtu);//将字符串写入filter_str
	if( -1==pcap_compile(source_pcap_t, &filter, filter_str, 1, 0) )//过滤
	{
		printf("pcap_compile() fail.\n");
		printf("errno:%s\n", pcap_geterr(source_pcap_t));//获取出错信息，返回最后一次pcap库函数操作失败的原因，如果网卡句柄已经关闭，那么指针指向的出错信息无效的，需要在关闭之前把信息拷贝出来
		exit_main();
	}
	if( -1==pcap_setfilter(source_pcap_t, &filter) )//指定过滤程序，第二个参数参数是bpf_program结构指针通常取自pcap_compile()函数调用
	{
		printf("pcap_setfilter() fail.\n");
		exit_main();
	}

	struct pcap_pkthdr *packet;//包头
	const u_char *pktStr;//包数据
	int s=pcap_next_ex(source_pcap_t, &packet, &pktStr);//从网口或离线文件获得一个报文，第一个参数为网卡句柄（文件描述符）
	while( s > 0 )                                       //第二个参数为包头（packet header）第三个为包数据，返回值大于0成功
	{
		if( NULL==pktStr )
		{
			printf("pcap_next() return NULL.\n");
			break;		
		}
		else
		{
			printf("Packet length: %d\n", packet->len);  //包的长度
			printf("Number of bytes: %d\n", packet->caplen); //实际捕获的包的长度 ，有可能捕获时终止，导致小于len
			printf("Recieved time: %s\n", ctime((const time_t *)&packet->ts.tv_sec));
			//读到的数据包写入生成pcap文件
			pcap_dump((u_char*)des_pcap_dumper_t, packet, pktStr);//向调用pcap_dump_open打开的文件写入一个数据包
		}		                                                //第一个参数为pcap_dump_open的返回值（要强转），
		s=pcap_next_ex(source_pcap_t, &packet, &pktStr);
	}

	pcap_dump_close(des_pcap_dumper_t);//关闭网络包文件
	pcap_close(source_pcap_t);//关闭网络接口
}






void write_pcap()
{
	pcap_dumper_t *pdumper;
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	if( NULL==(source_pcap_t=pcap_open_offline("gl_icmp.pcap", errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		exit_main();
	}
	//打开保存的pcap文件	
	if( NULL==(pdumper=pcap_dump_open(source_pcap_t,"./chongzu.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		exit_main();		
	}

	
	MyNode *p = list ->first;
	while(p)
	{
		Packet *packet = (Packet *)p->data;//将链表节点的数据类型转（void*）换为Packet类型
		pcap_dump((u_char*)pdumper, packet->hdr, packet->data);//写入一个数据包到pcap_dump_open函数打开的文件./final.pcap
		p=p->next;
	}
	

	pcap_dump_flush(pdumper);//将输出缓冲区刷新到“savefile”，这样任何用pcap_dump写入但尚未写入“savefile”的包都将被写入
	pcap_dump_close(pdumper);//
	pcap_close(source_pcap_t);

}


void if_reassembled(char *file)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((fp = pcap_open_offline(file,	   // name of the device
					errbuf					                    // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", file);
		return ;
	}
	
	pcap_loop(fp, 0, handle_packet, NULL);//捕获并处理所有包（第二个参数为0时），第一个参数为包文件描述符，
	printf("捕获完毕\n");
	pcap_close(fp);                           
	
}





int main(int argc, char *argv[])
{

		
	/*	filter_pcap(argv[1]);//过滤文件中的包，并将过滤结果写入./gl_icmp.pcap
		list = createMyList();//定义一个链表，数据为包头加数据
		print_pcap("gl_icmp.pcap");	//捕获并处理数据包（通过回调函数实现分片,将分片包写入链表）
		write_pcap();//将保存在链表中的分片包写入新的pcap文件
		
		printf("\n%d \n", list->length);
		freeMyList(list,free_data);//释放链表
	*/
	
	
		printf("%s\n", argv[1]);
		list_reassembled = createMyList();
		if_reassembled(argv[1]);//能否重组
		printf("list_reassembled->length=%d\n", list_reassembled->length);
		//write_pcap();
		freeMyList(list_reassembled, free_data_1);
		list_reassembled = NULL;
	return 0;
}






