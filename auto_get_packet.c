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

//�����ⲿ��ȫ�ֱ���������
extern int fragment_length;      //��Ƭ֮�󳤶�
extern int fragment_filter_length ;
extern int reassemble_length  ;  //����֮�󳤶ȣ�
extern int fragment_filter_packet ;

extern pcap_t *file_fragment ;
extern pcap_t *file_reassemble ;
extern pcap_t *source_pcap_fragment;
extern pcap_dumper_t *pdumper_fragment ;
extern pcap_dumper_t *pdumper_reassembled ;
extern pcap_t *source_pcap_reassembled ;

extern int is_foc ;//�����Ƿ�Ƭ�����飺      -c�ı�ǣ��޲���
extern int is_autogetpacke ;//�����Զ�������ץ��      -a�ı��
extern char *writefile ;//��ʼ��д����ļ���        -w�Ĳ���
extern int write_pcap_flag;        //-w �ı��
extern char *network ;//��������ӿ���                         -a�Ĳ���
extern int auto_get_packet_size ;//Ĭ��ץ������Ϊ500                  -s�Ĳ���
extern int mtu;//Ĭ��mtuΪ1500 


/*
Ifreq�ṹ��������ip��ַ������ӿڣ�����MTU��
��Linuxϵͳ�л�ȡIP��ַͨ������ͨ��ifconfig������ʵ�ֵģ�
Ȼ��ifconfig����ʵ����ͨ��ioctl�ӿ����ں�ͨ�ţ�ifconfig�������ȴ�һ��socket��
Ȼ�����ioctl��request���ݵ��ںˣ��Ӷ���ȡrequest�������ݡ�
��������ӿڵ����������õĳ�ʼ����֮һ���Ǵ��ں˻�ȡ������ϵͳ�е����нӿڡ�
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
    lint ifc_len;//����������нӿ���Ϣ�Ļ��������ܳ���
    union{
        caddr_t  ifcu_buf//������нӿ���Ϣ�����struct ifreq���Ļ�����
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
	struct ifconf ifc;//�����������нӿ���Ϣ��ÿ���ӿڰ����ӿ�����������Ϣ����struct ifreq��
	char buf[512];
	struct ifreq *ifr;//��������ip��ַ��MTU�Ƚӿ���Ϣ�Ľӿ�
	//��ʼ��ifconf
	ifc.ifc_len = 512;//����������нӿ���Ϣ�Ļ������ĳ���
	ifc.ifc_buf = buf;//��Žӿ���Ϣ�Ļ�����

	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)//��һ�����ں�ͨ�ŵ�socket
	{
		perror("socket");
	}  
	ioctl(sockfd, SIOCGIFCONF, &ifc); //���ں�ͨ�ţ�SIOCGIFCONF��ȡ���нӿ��б�������ifc��

	//��������ȡ�������������
	ifr = (struct ifreq*)buf;  //��ifrָ��ӿ���Ϣ������
	for(i=(ifc.ifc_len/sizeof(struct ifreq)); i>0; i--)//�ӿ�����=���нӿ���Ϣ�ĳ��ȳ�/һ���ӿڵĳ���
	{
		if(strcmp(ifr->ifr_name,str) == 0)//�ж�strָ����ַ����Ƿ�Ϊ���صĽӿ���
			return 1;
		ifr++;//ָ����һ���ӿ�
	}
	return 0;
}

void autogetpacket(char *Netport,char *writefile)
{
	pcap_t *handle;                 // �Ự��� 
	pcap_dumper_t* out_pcap;
	char errbuf[PCAP_ERRBUF_SIZE]; // �洢������Ϣ���ַ���

	bpf_u_int32 mask;               //������������� 
	bpf_u_int32 net;                // ������IP��ַ 

	char *dev = Netport;                      //ָ����Ҫ��ץ�����豸 ������linux�µ������豸eth0��lo�ֱ��������ͱ��ػ���
	pcap_lookupnet(dev, &net, &mask, errbuf);

	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);//��ȡ�������
	
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
	//��������callback�����Լ��������Ǿ�ֻ��ͨ��pcap_loop�����һ������user��ʵ����
	pcap_loop(handle,auto_get_packet_size,dispatcher_handler,(u_char *)out_pcap);//����ÿһ���������˺ͷ�Ƭ��

	printf("\nget %d packets\n",auto_get_packet_size);//ץ���İ�������
	printf("%d packets after filter\n", auto_get_packet_size-fragment_filter_packet);//���˺�İ�������
	printf("%d packets after fragment\n",fragment_length);//���а���Ƭ���������

	pcap_close(handle);
	pcap_dump_flush(out_pcap);
	pcap_dump_close(out_pcap);
}