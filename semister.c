#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <libconfig.h>
 
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
 
#define SIZE_ETHERNET 14

// Declaring count variables
static long icmp = 0;
static long igmp = 0;
static long others = 0;
static long udp = 0;
static long tcp = 0;
static double icmp_sum = 0;
//static double igmp_sum = 0;
//static double others_sum = 0;
static double udp_sum = 0;
static double tcp_sum = 0;
static long total_count = 0;  // Total no. of packets
static int total_unique_ips = 0;

// Declaring memory variables
static long ICMP_prevMillisecond;
static time_t ICMP_prevSecond;

static long TCP_prevMillisecond;
static time_t TCP_prevSecond;

static long UDP_prevMillisecond;
static time_t UDP_prevSecond;

static double ICMP_Delays[100];
static double TCP_Delays[500];
static double UDP_Delays[100];

static int command_line_options = 0;
static int TCP_Allow = 0;
static int UDP_Allow = 0;
static int ICMP_Allow = 0;
static int IGMP_Allow = 0;

static int no_of_packets = 0;

static FILE *ICMP_fp;
static FILE *TCP_fp;
static FILE *UDP_fp;
static FILE *log_fp;
static FILE *stat_fp;

void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int ); 
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int);
void TCP_timeSeries(const struct pcap_pkthdr *pkthdr);
void UDP_timeSeries(const struct pcap_pkthdr *pkthdr);
void ICMP_timeSeries(const struct pcap_pkthdr *pkthdr);
void *ThreadFunction(void *threadId);
void statsOfPackets(long period);
void insertPacketInPacketStore(char *str,int code);
//void packetDatabase(const struct sniff_ip *ip, int code);
void print_time(int flag);
void closeAllFilePointers(); 

struct keyvalue
{
	char ip_addr[20];
	int count;
	char* type_of_packet;
}packetStore[100];

struct sniff_ip
{
	u_char ip_vhl;
	u_char ip_tos;
	u_char protocol;
	struct in_addr ip_src,ip_dst;
};

struct sockaddr_in source,dest;
int i,j;

void packetDatabase(const struct sniff_ip *ip, int code)
{
	searchPacketInPacketStore(inet_ntoa(ip->ip_src),code);
}
 
static pcap_t *handle; //Handle of the device that shall be sniffed

int main(int argc , char* argv[])
{
	pcap_if_t *alldevsp , *device;
	pthread_t thread;
	long tid = 1;
 
    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;
     
	/*Start parsing configuration file*/
		
	config_t cfg;
	config_setting_t *setting;

	config_init(&cfg);
	
	if(! config_read_file(&cfg, "example.cfg"))
	{
    		printf("File not found");
    	}
	else
	{
		setting = config_lookup(&cfg,"transport_protocol");
		command_line_options = 1;
		int count = config_setting_length(setting);
		int i = 0;
		char *str;
		for(i;i<count;i++)
		{
			str = config_setting_get_string_elem(setting,i);
			printf("%s\n",str);
			if(strcmp(str,"TCP") == 0)
			{
				TCP_Allow = 1;													
			}

			if(strcmp(str,"UDP") == 0)
			{
				UDP_Allow = 1;
			}

			if(strcmp(str,"ICMP") == 0)
			{
				ICMP_Allow = 1;
			}

			if(strcmp(str,"IGMP") == 0)
			{
				IGMP_Allow = 1;
			}

		}		
	}
	
	//First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");
     
    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
     
    //Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];
     
    //Open the device for sniffing
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");
    
	ICMP_fp = fopen("ICMP_Delays.txt","a");
	TCP_fp = fopen("TCP_Delays.txt","a");
	UDP_fp = fopen("UDP_Delays.txt","a"); 
    log_fp = fopen("archive.txt","a");
    if(log_fp==NULL || UDP_fp==NULL || TCP_fp==NULL || ICMP_fp==NULL)
    {
        printf("Unable to create file.");
    }
    
	printf("\n\n\n\n");
	print_time(1); 

	pcap_setdirection(handle,PCAP_D_IN);	
	int rc = pthread_create(&thread,NULL,ThreadFunction,(void *)tid);	

    pcap_loop(handle , -1 , got_packet , NULL);
	
	//pcap_freecode(&fp);
	pcap_close(handle);  
    return 0;  
} // MAIN ENDS..
 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{    
	total_count++;
	int size = header->len;
    printf("\n\n=====================================================================\n");  
    printf("Packet:- %ld", total_count);
	
//Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	struct sniff_ip *ip = (struct sniff_ip*)(buffer + sizeof(struct ethhdr));
	
    if(command_line_options == 0)
	{
		switch (iph->protocol) //Check the Protocol and do accordingly...
	    {
        case 1:  //ICMP Protocol
			printf("   Protocol: ICMP\n");
            ++icmp;
			packetDatabase(ip,3);
            print_icmp_packet( buffer , size);
			ICMP_timeSeries(header);  //calling function for delay calculation
            break;
         
        case 2:  //IGMP Protocol
			printf("   Protocol: IGMP\n");
            ++igmp;
			packetDatabase(ip,4);
            break;
         
        case 6:  //TCP Protocol
			printf("   Protocol: TCP\n");
            ++tcp;
			packetDatabase(ip,1);
            print_tcp_packet(buffer , size);
			TCP_timeSeries(header);  //calling function for delay calculation
            break;
         
        case 17: //UDP Protocol
			printf("   Protocol: UDP\n");
            ++udp;
			packetDatabase(ip,2);
            print_udp_packet(buffer , size);
			UDP_timeSeries(header);  //calling function for delay calculation
            break;
         
        default: //Some Other Protocol like ARP etc.
			printf("   Protocol: Unknown\n");
            ++others;
            break;
    }
}
else if(command_line_options == 1)
	{
		switch (iph->protocol) //Check the Protocol and do accordingly...
	    {
        case 1:  //ICMP Protocol
			if(ICMP_Allow == 1){
			printf("   Protocol: ICMP\n");
            ++icmp;
			packetDatabase(ip,3);
            print_icmp_packet( buffer , size);
			}
            break;
         
        case 2:  //IGMP Protocol
			if(IGMP_Allow == 1){
			printf("   Protocol: IGMP\n");
            ++igmp;
			packetDatabase(ip,4);
			}
            break;
         
        case 6:  //TCP Protocol
			if(TCP_Allow == 1){
			printf("   Protocol: TCP\n");
            ++tcp;
			packetDatabase(ip,1);
            print_tcp_packet(buffer , size);
			}
            break;
         
        case 17: //UDP Protocol
			if(UDP_Allow == 1){
			printf("   Protocol: UDP\n");
            ++udp;
			packetDatabase(ip,2);
            print_udp_packet(buffer , size);
			}
            break;
         
        default: //Some Other Protocol like ARP etc.
			printf("   Protocol: Unknown\n");
            ++others;
            break;
    }
}
    printf("TCP:%ld   UDP:%ld   ICMP:%ld   IGMP:%ld   Others:%ld   Total : %ld\r", tcp , udp , icmp , igmp , others , total_count);
}
 
void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    fprintf(log_fp , "\n");
    fprintf(log_fp , "Ethernet Header\n");
    fprintf(log_fp , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(log_fp , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(log_fp , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
 
void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size); //calling etherner header func
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(log_fp , "\n");
    fprintf(log_fp , "IP Header\n");
    fprintf(log_fp , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(log_fp , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(log_fp , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(log_fp , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(log_fp , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(log_fp , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(log_fp , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(log_fp , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(log_fp , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(log_fp , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(log_fp , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(log_fp , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(log_fp , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );

	printf("IP:- %s --->> " , inet_ntoa(source.sin_addr) );
    printf("%s" , inet_ntoa(dest.sin_addr) );
}
 
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
         
	fprintf(log_fp , "\n\n***********************TCP Packet*************************\n"); 
         
    print_ip_header(Buffer,Size);  //calling IP header func
    printf("\tPort: %u --->> ",ntohs(tcph->source));
    printf(" %u",ntohs(tcph->dest));
	printf("\nFlags:-  ");
	//printf("CRW:%d\t",(unsigned int)tcph->crw);
	//printf("ECE:%d\t",(unsigned int)tcph->ece);
	printf("URG:%d\t",(unsigned int)tcph->urg);
	printf("ACK:%d\t",(unsigned int)tcph->ack);
	printf("PSH:%d\t",(unsigned int)tcph->psh);
	printf("RST:%d\t",(unsigned int)tcph->rst);
	printf("SYN:%d\t",(unsigned int)tcph->syn);
	printf("FIN:%d\t",(unsigned int)tcph->fin);
	printf("\n");	
	 
    fprintf(log_fp , "\n");
    fprintf(log_fp , "TCP Header\n");
    fprintf(log_fp , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(log_fp , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(log_fp , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(log_fp , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(log_fp , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(log_fp , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(log_fp , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(log_fp , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(log_fp , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(log_fp , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(log_fp , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(log_fp , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(log_fp , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(log_fp , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(log_fp , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(log_fp , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(log_fp , "\n");
    fprintf(log_fp , "                        DATA Dump                         ");
    fprintf(log_fp , "\n");
         
    fprintf(log_fp , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(log_fp , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(log_fp , "Data Payload\n");   
    PrintData(Buffer + header_size , Size - header_size );
                         
    fprintf(log_fp , "\n###########################################################");
}
 
void print_udp_packet(const u_char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    
    fprintf(log_fp , "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);          
     
    fprintf(log_fp , "\nUDP Header\n");
    fprintf(log_fp , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(log_fp , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(log_fp , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(log_fp , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(log_fp , "\n");
    fprintf(log_fp , "IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(log_fp , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    fprintf(log_fp , "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);
     
    fprintf(log_fp , "\n###########################################################");
}
 
void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(log_fp , "\n\n***********************ICMP Packet*************************\n");
     
    print_ip_header(Buffer , Size);
             
    fprintf(log_fp , "\n");
         
    fprintf(log_fp , "ICMP Header\n");
    fprintf(log_fp , "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(log_fp , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(log_fp , "  (ICMP Echo Reply)\n");
    }
     
    fprintf(log_fp , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(log_fp , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(log_fp , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(log_fp , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(log_fp , "\n");
 
    fprintf(log_fp , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(log_fp , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(log_fp , "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
     
    fprintf(log_fp , "\n###########################################################");
}
 
void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(log_fp , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(log_fp , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(log_fp , "."); //otherwise print a dot
            }
            fprintf(log_fp , "\n");
        }
         
        if(i%16==0) fprintf(log_fp , "   ");
            fprintf(log_fp , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(log_fp , "   "); //extra spaces
            }
             
            fprintf(log_fp , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(log_fp , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(log_fp , ".");
                }
            }
             
            fprintf(log_fp ,  "\n" );
        }
    }
}
void ICMP_timeSeries(const struct pcap_pkthdr *pkthdr)
{
	struct timespec spec;
	long m_sec;
	long pkt_msec;
	time_t sec,pkt_sec;
	char* time_str;
	double actual_delay;

	clock_gettime(CLOCK_REALTIME,&spec);
	sec = spec.tv_sec;
	//m_sec = round(spec.tv_nsec / 1.0e6);

	pkt_sec = pkthdr->ts.tv_sec;
	pkt_msec = pkthdr->ts.tv_usec;	
	
	double f = (pkt_msec*0.000001)+pkt_sec;
	//printf("\t\t\t\t%ld \n",(pkt_sec));
	//printf("%f \n",f);
	time_str = 	ctime(&sec);
	printf("\nPacket Captured at %s",time_str);
	
	// Compute delays
	if(icmp >1)
	{

		actual_delay = (ICMP_prevMillisecond*0.000001)+ICMP_prevSecond;
		double temp = f-actual_delay;		
		fprintf(ICMP_fp,"%.3f\n",temp);
		printf("\tInter-packet Delay : %f sec\n\n",temp);	
		icmp_sum+=temp;  // incrementing sum of icmp delays		
		
		ICMP_Delays[icmp] = temp;
	
		ICMP_prevSecond = pkt_sec;
		ICMP_prevMillisecond = pkt_msec;
			
	}
	else
	{
		ICMP_prevMillisecond = pkt_msec;
		ICMP_prevSecond = pkt_sec;
	}
}

void TCP_timeSeries(const struct pcap_pkthdr *pkthdr)
{
	struct timespec spec;
	long m_sec;
	long pkt_msec;
	time_t sec,pkt_sec;
	char* time_str;
	double actual_delay;

	clock_gettime(CLOCK_REALTIME,&spec);
	sec = spec.tv_sec;

	pkt_sec = pkthdr->ts.tv_sec;
	pkt_msec = pkthdr->ts.tv_usec;	
	
	double f = (pkt_msec*0.000001)+pkt_sec;
	
	time_str = 	ctime(&sec);
	printf("\nPacket Captured at %s",time_str);
	
	// Compute delays
	if(tcp >1)
	{

		actual_delay = (TCP_prevMillisecond*0.000001)+TCP_prevSecond;
		double temp = f-actual_delay;	
		fprintf(TCP_fp,"%.3f\n",temp);	
		printf("\tInter-packet Delay : %f sec\n\n",temp);			
		tcp_sum+=temp;  // incrementing sum of tcp delays
		
		TCP_Delays[tcp] = temp;
	
		TCP_prevSecond = pkt_sec;
		TCP_prevMillisecond = pkt_msec;
			
	}
	else
	{
		TCP_prevMillisecond = pkt_msec;
		TCP_prevSecond = pkt_sec;
	}
}

void UDP_timeSeries(const struct pcap_pkthdr *pkthdr)
{
	struct timespec spec;
	long m_sec;
	long pkt_msec;
	time_t sec,pkt_sec;
	char* time_str;
	double actual_delay;

	clock_gettime(CLOCK_REALTIME,&spec);
	sec = spec.tv_sec;
	//m_sec = round(spec.tv_nsec / 1.0e6);

	pkt_sec = pkthdr->ts.tv_sec;
	pkt_msec = pkthdr->ts.tv_usec;	
	
	double f = (pkt_msec*0.000001)+pkt_sec;
	//printf("\t\t\t\t%ld \n",(pkt_sec));
	//printf("%f \n",f);
	time_str = 	ctime(&sec);
	printf("\nPacket Captured at %s",time_str);
	
	// Compute delays
	if(udp > 1)
	{

		actual_delay = (UDP_prevMillisecond*0.000001)+UDP_prevSecond;
		double temp = f-actual_delay;
		fprintf(UDP_fp,"%.3f\n",temp);		
		printf("\tInter-packet Delay : %f sec\n\n",temp);
		udp_sum+=temp;  // incrementing sum of udp delays			
		
		UDP_Delays[udp] = temp;
	
		UDP_prevSecond = pkt_sec;
		UDP_prevMillisecond = pkt_msec;
			
	}
	else
	{
		UDP_prevMillisecond = pkt_msec;
		UDP_prevSecond = pkt_sec;
	}
}

void *ThreadFunction(void *threadId)
{
	long tid;
	long period = 10000000;  // this is period for the program to run [same value as usleep() function]
	tid = (long)threadId;

	usleep(10000000);

	printf("\n\nExiting\n\n");
	pcap_close(handle);

	statsOfPackets(period);
	closeAllFilePointers();
	 //error is coming here
	exit(1);
}
void statsOfPackets(long period)
{
	long period_sec = (period/1000000);
	double total_delay=0;
	total_delay=icmp_sum+tcp_sum+udp_sum;
	int first_time = 0;	
	
	if(fopen("Final_Stats.txt","r") == NULL)
	{
		first_time = 1;
	}	
	stat_fp = fopen("Final_Stats.txt","a");


	printf("\n\n\n\n");
	print_time(0);	

	printf("\n\t\t\t\t ----Statistics---- \n");
	printf("===============================================================================");
	printf("\t\t Total Packets : %ld\n\n",total_count);
	printf("\t\t Total ICMP Packets : %ld\n",icmp);
	printf("\t\t Total IGMP Packets : %ld\n",igmp);
	printf("\t\t Total TCP Packets  : %ld\n",tcp);
	printf("\t\t Total UDP Packets  : %ld\n",udp);
	printf("\n\t\t Ratio of ICMP packets : %.3f\n",((double)icmp/total_count)*100);
	printf("\n\t\t Ratio of IGMP packets : %.3f\n",((double)igmp/total_count)*100);
	printf("\n\t\t Ratio of TCP packets : %.3f\n",((double)tcp/total_count)*100);
	printf("\n\t\t Ratio of UDP packets : %.3f\n",((double)udp/total_count)*100);
	printf("===============================================================================");
	for(int i = 0 ; i < total_unique_ips ; i++)
	{
		printf("\nid : %s \t count : %d  ------ (%s)\n",packetStore[i].ip_addr,packetStore[i].count,packetStore[i].type_of_packet);
	}

	fprintf(stat_fp,"#----STATISTICS----# \n");
	fprintf(stat_fp,"#======================================================================================#\n");
	
	if(first_time == 1)
	{	
		fprintf(stat_fp,"\n\n\t\t\t\tICMP\tIGMP\tTCP\tUDP\tOTHERS\tTOTAL\n");
	}

	fprintf(stat_fp,"#----------------------------------------------------------#\n\n");
	//fprintf(stat_fp,"\t\t\t  |\t |\t |\t|  \t| \t|\n");
	fprintf(stat_fp,"#Total_Packets\n\t\t\t\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n\n",icmp,igmp,tcp,udp,others,total_count);
	//fprintf(stat_fp,"\t\t\t  |\t |\t |\t|  \t| \t|\n");
	fprintf(stat_fp,"#Packets_Ratio\n\t\t\t\t%.2f\t%.2f\t%.2f\t%.2f\t %.2f\t%.2f\n\n",((double)icmp/total_count)*100,((double)igmp/total_count)*100, ((double)tcp/total_count)*100,((double)udp/total_count)*100,((double)others/total_count)*100,((double)total_count/total_count)*100);

	fprintf(stat_fp,"#Packets/second\n\t\t\t\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\n\n",(double)icmp/period_sec,(double)igmp/period_sec,(double)tcp/period_sec,(double)udp/period_sec,(double)others/period_sec,(double)total_count/period_sec);
	fprintf(stat_fp,"#Average_Delays\n\t\t\t\t%.2f\t-\t%.2f\t%.2f\t-\t%.2f\n\n",(double)icmp_sum/icmp,(double)tcp_sum/tcp,(double)udp_sum/udp,(double)total_delay/total_count);
	fprintf(stat_fp,"#======================================================================================#\n\n");

	/*for(int i = 0 ; i < total_unique_ips ; i++)
	{
		fprintf(stat_fp,"\nid : %s \t count : %d  ------ (%s)\n",packetStore[i].ip_addr,packetStore[i].count,packetStore[i].type_of_packet);
	}

	*/fclose(stat_fp);	
}

void insertPacketInPacketStore(char *str,int code)
{
printf("\n\t installing new entry\n");
	strcpy(packetStore[total_unique_ips].ip_addr,str);
	packetStore[total_unique_ips].count = 1;
	
	switch(code)
	{
		case 1:
			packetStore[total_unique_ips].type_of_packet = "TCP";
			break;
		case 2:
			packetStore[total_unique_ips].type_of_packet = "UDP";
			break;
		case 3:
			packetStore[total_unique_ips].type_of_packet = "ICMP";
			break;
		case 4:
			packetStore[total_unique_ips].type_of_packet = "IGMP";
			break;
	}
}
void searchPacketInPacketStore(char *str,int code)
{
	for(int i = 0; i < total_unique_ips ; i++)
	{
		// Compare the id with every object's id in the array	
		if( (strcmp(str,packetStore[i].ip_addr) == 0))
		{	
			packetStore[i].count++;
			return;
		}
	}
	insertPacketInPacketStore(str,code);
	
	total_unique_ips++;
}

void print_time(int flag)
{
    long            ms; // Milliseconds
    time_t          s;  // Seconds
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    s  = spec.tv_sec;
    ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to microseconds

	time_t current_time;
    char* c_time_string;

	ms = ms/1000;

	s = s + ms;

	current_time = s;

	c_time_string = ctime(&current_time);
	if(flag == 1)
	{
		(void) printf("\t\t\tStarting time is %s\n", c_time_string);
		//start_time_string= ctime(&current_time);
		stat_fp = fopen("Final_Stats.txt","a");
		fprintf(stat_fp,"\n\n#'(SESSION TIME PERIOD)'");
		fprintf(stat_fp,"\t\t\t\tStarted:-  %s",c_time_string);
		fclose(stat_fp);		
		}
	
	else
	{
		(void) printf("\t\t\tEnding time is %s\n", c_time_string);

		fprintf(stat_fp,"#~~~~~~~~~~~~~~~~~~~~~");
		fprintf(stat_fp,"\t\t\t\tFinished:- %s",c_time_string);
	}
}
void closeAllFilePointers()
{

	fclose(log_fp);
	fclose(ICMP_fp);
	fclose(TCP_fp);
	fclose(UDP_fp);
}
