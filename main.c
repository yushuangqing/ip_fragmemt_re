#include "fragment.h"
#include "auto_get_packet.h"
#include "reassembled.h"
#include "list.h"

#include <arpa/inet.h>
#include <dirent.h> 
#include <endian.h>
#include <getopt.h>
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

//
int fragment_length = 0;      //分片之后长度
int fragment_filter_length = 0;
int reassemble_length = 0 ;  //重组之后长度；
int fragment_filter_packet = 0;

pcap_t *file_fragment = NULL;
pcap_t *file_reassemble = NULL;
pcap_t *source_pcap_fragment=NULL;
pcap_t *source_pcap_reassembled = NULL;
pcap_dumper_t *pdumper_fragment = NULL;
pcap_dumper_t *pdumper_reassembled = NULL;


int is_foc = 0;//定义是分片或重组：      -c的标记，无参数
int is_autogetpacke = 0;//定义自动从网口抓包      -a的标记
char *writefile = "final.pcap";//初始化写入的文件名        -w的参数
int write_pcap_flag = 0;        //-w 的标记
char *network = NULL;//定义网络接口名                         -a的参数
int auto_get_packet_size = 500;//默认抓包数量为500                  -s的参数
int mtu = 1500;//默认mtu为1500                                          -m的参数

MyList *list_reassembled = NULL;


int main(int argc, char *argv[])
{	
	int opt;//选项

	while ((opt = getopt(argc, argv, "m:a:cw:s:")) != -1)
	{
		switch (opt) 
		{
			case 'm':
				mtu=atoi(optarg);//将带选项的参数字符串转成整数（指定最大传输单元）
				break;
			case 'a':
				if(junge_networkcard(optarg) == 0)//判断是否为本地的网络接口
				{
					printf("%s 不是网卡\n",optarg);
					return 1;
				}
				network = optarg;//网络接口为选项a后的参数
				is_autogetpacke = 1;
				break;
			case 'c':
				is_foc = 1;//重组
				break;
			case 'w':
				writefile = optarg;//写入的文件名为选项w后的参数
				write_pcap_flag = 1;
				break;
			case 's':
				auto_get_packet_size = atoi(optarg);//抓包的长度为选项s后的参数
				break;
			case '?':
				printf("Unknown option: %c\n",(char)optopt);
				break;
			default :
				printf("输入的非法\n");
				break;
		}

	}
	
	/*************************** 处理选项 ************************************/
	
	if(is_autogetpacke == 0)//从本地读取pcap文件
	{
		if(optind != argc)//有文件输入(该文件为非选项的参数)
		{
			if( is_foc == 0)//分片
			{
				char errbuf[PCAP_ERRBUF_SIZE]={0};//保存打开错误信息
				source_pcap_fragment=pcap_open_offline(argv[optind], errbuf);
				
				if( NULL == source_pcap_fragment)//source_pcap_fragment为网卡句柄或文件描述符
				{
					printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
					return 1;
				}
				
				//打开指定写入writefile文件	，pdumper_fragment为保存文件的描述符
				if(write_pcap_flag == 1)//写入制定的文件
				{
					pdumper_fragment = pcap_dump_open(source_pcap_fragment,writefile);
					if( NULL == pdumper_fragment)//转存数据包，打开用于保存捕获数据包的文件，用于写入。
					{
						printf("pcap_dump_open() fail.\n");
						pcap_close(source_pcap_fragment);//如果打开失败，关闭前面打开的网口或者文件
						return 1;
					}
				}
				else//写入默认的文件
				{
					pdumper_fragment  = pcap_dump_open(source_pcap_fragment,"./after_fragment.pcap");
				}

				//处理多个文件
				for(int i = optind; i < argc ; i++)
				{
					printf("处理%s \n",argv[i]);
					fragment_packet(argv[i]);//处理所有要分片的包
					printf("\n");
				}

				pcap_dump_flush(pdumper_fragment);//将输出缓冲区刷新到“savefile”，
				pcap_dump_close(pdumper_fragment);//关闭网络包文件
				pcap_close(source_pcap_fragment);//关闭网络接口或文件
			}
			else//重组
			{
				char errbuf[PCAP_ERRBUF_SIZE]={0};
				if( NULL==(source_pcap_reassembled=pcap_open_offline(argv[optind], errbuf)) )
				{
					printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
					return 1;
				}
				
				//打开保存的pcap文件	
				if(write_pcap_flag == 1)//写入制定的文件
				{
					if( NULL==(pdumper_reassembled=pcap_dump_open(source_pcap_reassembled,writefile)) )
					{
						printf("pcap_dump_open() fail.\n");
						pcap_close(source_pcap_reassembled);//如果打开失败，关闭前面打开的网口或者文件
						return 1;
					}
				}
				else//写入默认的文件
				{
					pdumper_reassembled  = pcap_dump_open(source_pcap_reassembled,"./after_reassembled.pcap");
				}

				for(int i = optind; i < argc ; i++)
				{
					printf("处理%s\n",argv[i]);
					reassembled(argv[i]);//处理所有要重组的包
					printf("\n");
				}

				pcap_dump_flush(pdumper_reassembled);//将输出缓冲区刷新到“savefile”，
				pcap_dump_close(pdumper_reassembled);//关闭网络包文件
				pcap_close(source_pcap_reassembled);//关闭网络接口或文件
			}
		}
		else//无非选项参数的文件输入
		{
			printf("please input file\n");
			return 1;
		}
	}
	else
	{
		autogetpacket(network,writefile);//从指定网口抓包
	}
	
	return 0;
}






