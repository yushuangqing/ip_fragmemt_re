#include "auto_get_packet.h"
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

//引用外部的全局变量的声明
extern int fragment_length;      //分片之后长度
extern int fragment_filter_length ;
extern int reassemble_length  ;  //重组之后长度；
extern int fragment_filter_packet ;

extern pcap_t *file_fragment ;
extern pcap_t *file_reassemble ;
extern pcap_t *source_pcap_fragment;
extern pcap_dumper_t *pdumper_fragment ;
extern pcap_dumper_t *pdumper_reassembled ;
extern pcap_t *source_pcap_reassembled ;

extern int is_foc ;//定义是分片或重组：      -c的标记，无参数
extern int is_autogetpacke ;//定义自动从网口抓包      -a的标记
extern char *writefile ;//初始化写入的文件名        -w的参数
extern int write_pcap_flag;        //-w 的标记
extern char *network ;//定义网络接口名                         -a的参数
extern int auto_get_packet_size ;//默认抓包数量为500                  -s的参数
extern int mtu;//默认mtu为1500 


/*
Ifreq结构用来配置ip地址，激活接口，配置MTU。
在Linux系统中获取IP地址通常都是通过ifconfig命令来实现的，
然而ifconfig命令实际是通过ioctl接口与内核通信，ifconfig命令首先打开一个socket，
然后调用ioctl将request传递到内核，从而获取request请求数据。
处理网络接口的许多程序沿用的初始步骤之一就是从内核获取配置在系统中的所有接口。
struct  ifreq  data;
fd = socket(AF_NET,SOCK_DGRAM,0);
ioctl(fd,SIOCGIFADDR,&data);

struct ifreq{
    char ifr_name[IFNAMSIZ];
    union{
        struct  sockaddr  ifru_addr;
        struct  sockaddr  ifru_dstaddr;
        struct  sockaddr  ifru_broadaddr;
        struct  sockaddr  ifru_netmask;
        struct  sockaddr  ifru_hwaddr;
        short  ifru_flags;
        int     ifru_metric;
        caddr_t ifru_data;
    }ifr_ifru;
};
#define ifr_addr        ifr_ifru.ifru_addr
#define ifr_broadaddr   ifr_ifru.ifru_broadadd
#define ifr_hwaddr      ifr_ifru_hwaddr

struct ifconf{
    lint ifc_len;//用来存放所有接口信息的缓冲区的总长度
    union{
        caddr_t  ifcu_buf//存放所有接口信息（多个struct ifreq）的缓冲区
        struct   ifreq *ifcu_req;
    }ifc_ifcu
} 
#define    ifc_buf    ifc_ifcu.ifcu_buf
#define    ifc_req    ifc_ifcu.ifcu_req
*/

int junge_networkcard(char *str)
{
	int i=0;
	int sockfd;
	struct ifconf ifc;//用来保存所有接口信息。每个接口包括接口名和其他信息（见struct ifreq）
	char buf[512];
	struct ifreq *ifr;//用来配置ip地址，MTU等接口信息的接口
	//初始化ifconf
	ifc.ifc_len = 512;//用来存放所有接口信息的缓冲区的长度
	ifc.ifc_buf = buf;//存放接口信息的缓冲区

	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)//打开一个与内核通信的socket
	{
		perror("socket");
	}  
	ioctl(sockfd, SIOCGIFCONF, &ifc); //与内核通信，SIOCGIFCONF获取所有接口列表，保存在ifc中

	//接下来获取逐个网卡的名称
	ifr = (struct ifreq*)buf;  //将ifr指向接口信息缓冲区
	for(i=(ifc.ifc_len/sizeof(struct ifreq)); i>0; i--)//接口数量=所有接口信息的长度除/一个接口的长度
	{
		if(strcmp(ifr->ifr_name,str) == 0)//判断str指向的字符串是否为本地的接口名
			return 1;
		ifr++;//指向下一个接口
	}
	return 0;
}

void autogetpacket(char *Netport,char *writefile)
{
	pcap_t *handle;                 // 会话句柄 
	pcap_dumper_t* out_pcap;
	char errbuf[PCAP_ERRBUF_SIZE]; // 存储错误信息的字符串

	bpf_u_int32 mask;               //所在网络的掩码 
	bpf_u_int32 net;                // 主机的IP地址 

	char *dev = Netport;                      //指定需要被抓包的设备 我们在linux下的两个设备eth0和lo分别是网卡和本地环回
	pcap_lookupnet(dev, &net, &mask, errbuf);

	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);//获取网卡句柄
	
	if(write_pcap_flag == 1)
	{
		if( NULL==(out_pcap=pcap_dump_open(handle, writefile)))
		{
			printf("pcap_dump_open() fail.\n");
			pcap_close(handle);
			return ;
		}
	}
	else
	{
		if( NULL==(out_pcap=pcap_dump_open(handle,"./after_autogetpacket.pcap")))
		{
			printf("pcap_dump_open() fail.\n");
			pcap_close(handle);
			return ;
		}
	}
	//如果你想给callback传递自己参数，那就只能通过pcap_loop的最后一个参数user来实现了
	pcap_loop(handle,auto_get_packet_size,dispatcher_handler,(u_char *)out_pcap);//处理每一个包（过滤和分片）

	printf("\nget %d packets\n",auto_get_packet_size);//抓到的包的数量
	printf("%d packets after filter\n", auto_get_packet_size-fragment_filter_packet);//过滤后的包的数量
	printf("%d packets after fragment\n",fragment_length);//所有包分片后的总数量

	pcap_close(handle);
	pcap_dump_flush(out_pcap);
	pcap_dump_close(out_pcap);
}