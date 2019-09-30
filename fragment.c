#include "fragment.h"

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

//处理每一个包,temp1为pcap_loop()函数最后一个参数传递过来的
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if(is_autogetpacke == 1)//如果是网口自动抓取的包
	{
		printf("get a packet with length of [%d]\n",header->len);
	
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
		unsigned int ip_v = ip_head_s->ip_v;
		
		//过滤掉不能分片的包
		//printf("%d\n",header->len);
		//printf("%x\n",ip_off);
		//printf("%x\n",can_fragment);
		//printf("%d\n",ip_v);
		
		if(!((header->len > (mtu + MAC_HEAD)) 
					&& (can_fragment == 0)
					&& (ip_v == 4)))
		{
			fragment_filter_packet++;//不能分片的包的数量
			return ;
		}
	}

	if((mtu - IP_HEAD)%8 != 0)//判断ip的payload能否被8整除
		mtu = mtu - (mtu - IP_HEAD)%8;

	int num_ip_fragment = (header->len - MAC_HEAD - IP_HEAD - 1 )/(mtu - IP_HEAD) + 1;//每一个能分片的包能分成的片数
	fragment_length += num_ip_fragment;//所有包的分片的总数量

	const u_char *pdata =pkt_data + MAC_HEAD + IP_HEAD; //指向ip的payload
	
	for(int i=1;i<=num_ip_fragment;i++)//对每个分片包修改头部信息，包括ip长度、偏移量、校验和
	{
		Packet *packet = NULL;	
		packet = (Packet *)malloc(sizeof(Packet));
		if(packet == NULL)
			return ;
		if(i != num_ip_fragment)//如果不是最后一个分片包
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


			write_packet(pdumper_fragment,packet);//将修改后的分片包写入文件
			free_data(packet);	//释放申请的包空间
		}

		else //最后一个分片包
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
	if ((file_fragment = pcap_open_offline(file,	   // file_fragment文件描述符或网口句柄
					errbuf					                    // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", file);
		return ;
	}
	pcap_loop(file_fragment, 0, dispatcher_handler, NULL);//处理过滤后的每一个包，dispatcher_handler为回调函数
	pcap_close(file_fragment);
}


void filter_pcap(char *file)//过滤文件中的包
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
	if( NULL==(pdumper_filter=pcap_dump_open(source_pcap_filter,"./gl_ipv4.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		pcap_close(source_pcap_filter);

		return ;
	}

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
			const u_char *ip_head_data = pktStr + MAC_HEAD;//指向ip头部
			struct ip *ip_head_s = (struct ip *)ip_head_data;//强制将指向ip头部的数据转化为ip头部结构体
			u_short ip_off;//定义偏移量
			
			if (__BYTE_ORDER == __LITTLE_ENDIAN)//如果是小端
			{
				ip_off =htons(ip_head_s->ip_off);//偏移量
			}
			else
			{
				ip_off = ip_head_s->ip_off;
			}
			
			u_short can_fragment = ip_off & IP_DF;
			//u_short more_fragment = ip_off & IP_MF;	
			//u_short initoffset = ip_off & IP_OFFMASK;
			unsigned int ip_v = ip_head_s->ip_v;//ipv4

			if((can_fragment == 0) //过滤出能够分片而且数据帧长度大于mtu + MAC_HEAD的
					//&& (initoffset == 0)
					//&& (more_fragment == 0) 
					&& (packet->len > (mtu + MAC_HEAD)) 
					&& (ip_v == 4))
			{
				pcap_dump((u_char*)pdumper_filter, packet, pktStr);	//过滤出的数据包写入指定的pcap文件
				gllength++;
			}
		}		
		s=pcap_next_ex(source_pcap_filter, &packet, &pktStr);//处理下一个包
	}
	
	printf("过滤前有%d包\n",before_filter);
	printf("过滤后还有%d包\n",gllength);

	pcap_close(source_pcap_filter);
	pcap_dump_close(pdumper_filter);
}

void fragment_packet(char *filename)
{
	filter_pcap(filename);//过滤
	print_pcap("gl_ipv4.pcap");	
	printf("分片之后有%d包\n",fragment_length);
}
