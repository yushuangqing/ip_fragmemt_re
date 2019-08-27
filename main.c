#include <stdio.h>
#include <arpa/inet.h>
#include "pcap.h"
#include <stdlib.h>
#include <string.h>

#define PCAP_FILE "fgt1.pcap"

#define MTU 500
#define IP_HEAD 20
#define MAC_HEAD 14

typedef unsigned int  bpf_u_int32;
typedef unsigned short  u_short;
typedef int bpf_int32;



typedef struct pcap_file_header1 
{
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;    
	bpf_u_int32 sigfigs;   
	bpf_u_int32 snaplen;   
	bpf_u_int32 linktype;  
}pcap_file_header1;


typedef struct timestamp
{
	bpf_u_int32 timestamp_s;
	bpf_u_int32 timestamp_ms;
}timestamp;


typedef struct pcap_header
{
	timestamp ts;
	bpf_u_int32 capture_len;
	bpf_u_int32 len;
}pcap_header;

void print_fragment_data(char * data,size_t size)
{
	unsigned  short iPos = 0;
	if (data==NULL) 
	{
		return;
	}

	for (iPos=0; iPos < size/sizeof(unsigned short); iPos++) 
	{
		unsigned short a = ntohs( *((unsigned short *)data + iPos ) );
		if (iPos%8==0) printf("\n");
		if (iPos%4==0) printf(" ");
		printf("%04x",a);
	}
	printf("\n============\n");
}

int main (int argc, const char * argv[])
{
	pcap_file_header1  pfh;
	pcap_header  ph;
	int count=0;
	int readSize=0;
	int ret = 0;
	int num_ip_fragment = 0;
	
	FILE *fp = fopen(PCAP_FILE, "rw");
	if (fp==NULL) 
	{
		perror("fopen");
		return 1;
	}
	fread(&pfh, sizeof(pcap_file_header1), 1, fp);
	

	for (count=1; ; count++) 
	{
		readSize=fread(&ph, sizeof(pcap_header), 1, fp);
		if (readSize<=0)
			break;
		
		if(ph.capture_len > (MTU + MAC_HEAD))
		{
			num_ip_fragment = (ph.capture_len - MAC_HEAD - IP_HEAD)/(MTU - IP_HEAD) + 1;
			printf("num_ip_fragment = %d\n", num_ip_fragment);
			char *buf = (char *)malloc(sizeof(char)*(ph.capture_len));
			if (buf==NULL)
			{
				perror("malloc buf");
				return 1;
			}
			readSize=fread(buf, 1, ph.capture_len, fp);

			for(int i=1; i<=num_ip_fragment; i++)
			{
				if(i != num_ip_fragment)
				{
					char *buf_fragment = (char *) malloc ( sizeof(char) * (MAC_HEAD + MTU) );
					strncpy(buf_fragment, buf, MAC_HEAD+IP_HEAD);						
					strncat(buf_fragment, buf + MAC_HEAD + IP_HEAD + (i-1) * (MTU-IP_HEAD), (size_t)(MTU-IP_HEAD));
					//buf_fragment[MAC_HEAD + MTU] = '\0';
					print_fragment_data(buf_fragment, MAC_HEAD + IP_HEAD + MTU);
					free(buf_fragment);
					buf_fragment=NULL;
				}
				else
				{
					int num = ph.capture_len - (MTU-IP_HEAD) * (num_ip_fragment-1);
					char *buf_fragment = (char *)malloc(sizeof(char) * num);
					strncpy(buf_fragment, buf, MAC_HEAD+IP_HEAD);
					strncat(buf_fragment, buf + MAC_HEAD + IP_HEAD + (i-1) * (MTU-IP_HEAD), (size_t)(buf - MAC_HEAD - IP_HEAD - num_ip_fragment*(MTU-IP_HEAD)));
					//buf_fragment[num] = '\0';
					print_fragment_data(buf_fragment, num);
					free(buf_fragment);
					buf_fragment=NULL;
				}
			}

			printf("\n============\n");
			free(buf);
			buf=NULL;
		}			
		
		if (feof(fp) || readSize <=0 ) 
		{ 
			break;
		}
	}
	
	return 0;
}