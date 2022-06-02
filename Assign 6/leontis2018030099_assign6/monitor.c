#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

//Function prototypes
void process_packet(char * fname);
void usage(void);
void find_protocol(uint16_t src_port, uint16_t dst_port);
void find_retransmission(struct iphdr *ip, struct tcphdr *tcp);
 

//Struct for storing a network flow
struct packet_list
{
    uint8_t protocol;
    uint32_t  ip_src;
    uint32_t  ip_dst;
    uint16_t src_port;
    uint16_t dest_port;
};

int main(int argc, char *argv[])
{
    int ch;
    char *fname;
    if (argc < 2)
		usage();

    while ((ch = getopt(argc, argv, "hr")) != -1) {
		switch (ch) {		
		case 'r':
            fname=argv[2];
			process_packet(fname);
			break;
        default:
            usage();
        }
    }
    return 0;
}

void 
process_packet(char *fname)
{
    struct pcap_pkthdr *header;
    const u_char *packet;                /* The actual packet */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    const char *payload;
    unsigned short size_ip;

    int size_payload;
    int total_packs = 0;
    int tcp_counter = 0;
    int udp_counter = 0;
    int tcp_Bcounter = 0;
    int udp_Bcounter = 0;

    struct sockaddr_in source,dest;         /*Using this for printing uint32_t addresses*/
    struct packet_list list[5000];          /*Array of structs for storing network flows*/
    struct packet_list tmp;                 /*Temporary variable for making comparisons*/
    int list_counter=0;
    int tcp_flows_counter=0;
    int udp_flows_counter=0;
    bool found=false;                       /*Flagship*/
    
    //Pcap handler creation
    pcap_t *handler = pcap_open_offline(fname, error_buffer);
    if (handler == NULL){
        printf("Error: %s\n", error_buffer);
        exit(1);
    }

    //Repeat process for each packet into file
    while (pcap_next_ex(handler, &header, &packet) >= 0){   
        //Increase total packets counter and get ip header
        total_packs++;
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
        size_ip = ip->ihl * 4;
        
        memset(&source, 0, sizeof(source));
	    source.sin_addr.s_addr = ip->saddr;
	    memset(&dest, 0, sizeof(dest));
	    dest.sin_addr.s_addr = ip->daddr;
        
        if (size_ip < 20){
            printf("Invalid IP header length: %u bytes \n", size_ip);
        }else
        {   
            //Insert values into a temporary struct variable for later comparison
            //Last 2 values will be inserted after the protocol is defined
            tmp.protocol=ip->protocol;
            tmp.ip_src=ip->saddr;
            tmp.ip_dst=ip->daddr;
            
            switch (ip->protocol)
            {
                case IPPROTO_TCP:   
                    tcp_counter++;
        
                    //Get tcp header and check if valid              
                    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + size_ip);
                    int size_tcp = sizeof(struct ethhdr) + size_ip + tcp->doff*4;
                    if(size_tcp < 20){
                        printf("    * Invalid TCP header length: %u bytes\n", size_tcp);
                        break;
                    }
                    //Insert last 2 values into temporary struct variable
                    tmp.src_port=tcp->th_sport;
                    tmp.dest_port=tcp->th_dport;

                    //Print packet's info to user
                    printf("\nTCP Packet \n");
                    find_protocol(ntohs(tcp->th_sport),ntohs(tcp->th_dport));
                    printf("    Source Address: %s\n",inet_ntoa(source.sin_addr));      
                    printf("    Dest Address:  %s \n",inet_ntoa(dest.sin_addr));
                    printf("    Source port: %d\n",ntohs(tcp->th_sport));          
                    printf("    Destination port: %d\n",ntohs(tcp->th_dport));
                    
                    size_payload = header->len - size_tcp;
                    tcp_Bcounter += size_payload;
                    printf("    Header length: (%d bytes)   Payload : (%d bytes)\n",size_tcp,size_payload);
                    break;
                case IPPROTO_UDP:
                    udp_counter++;

                    //Get udp header             
                    struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + size_ip);
                    int size_udp = sizeof(struct ethhdr) + size_ip + sizeof(udp);
                    
                    //Insert last 2 values into temporary struct variable
                    tmp.src_port=udp->uh_sport;
                    tmp.dest_port=udp->uh_dport;
                    
                    //Print packet's info to user
                    printf("\nUDP Packet \n");
                    find_protocol(ntohs(udp->uh_sport),ntohs(udp->uh_dport));
                    printf("    Source Address: %s\n",inet_ntoa(source.sin_addr));
                    printf("    Dest Address: %s \n" ,inet_ntoa(dest.sin_addr));
                    printf("    Source port: %d\n", ntohs(udp->uh_sport));         
                    printf("    Destination port: %d\n", ntohs(udp->uh_dport));
                    
                    size_payload = header->len - size_udp;
                    udp_Bcounter += size_payload;
                    printf("    Header length: (%d bytes)   Payload : (%d bytes)\n",size_udp,size_payload);
                    break;
                default:
                    break;  //Skipps other protocols
            }
            
            //Only if current protocol is TCP or UDP
            if(tmp.protocol==IPPROTO_TCP || tmp.protocol==IPPROTO_UDP){
                found=false;
                //Search the array of structs and find all different struct variables (network flows)
                for(int i=0;i<list_counter;i++){
                    if(tmp.protocol==list[i].protocol){                                    
                        if(tmp.ip_src==list[i].ip_src       /*Same ips and ports*/
                            && tmp.ip_dst==list[i].ip_dst 
                            && tmp.src_port==list[i].src_port 
                            && tmp.dest_port==list[i].dest_port){
                           
                            found=true;
                            break;
                        }
                        else if(tmp.ip_src==list[i].ip_dst    /*Sender becomes receiver and receiver becomes sender*/
                                && tmp.ip_dst==list[i].ip_src  /*Inverted ips and ports, same network flow*/
                                && tmp.src_port==list[i].dest_port 
                                && tmp.dest_port==list[i].src_port){
                           
                                found=true;
                                break;
                        }                                                                                 
                    }
                }
                //If a same network flow was not found into struct array then insert it
                //Increase counter based on protocol
                if(!found){
                    if (tmp.protocol==IPPROTO_TCP)
                        tcp_flows_counter++;
                    else 
                        udp_flows_counter++;

                    list[list_counter]=tmp;
                    list_counter++;
                }
            }
        }
    }
    printf("\n____________________ PACKETS RECEIVED ____________________\n");
    printf("   Total packets received: %d\n"
           "\n   TCP packets received: %d"
           "\n   UDP packets received: %d\n"
           "\n   Total bytes of TCP packets received: %d"
           "\n   Total bytes of UDP packets received: %d\n"
           "\n   TCP network flows: %d"
           "\n   UDP network flows: %d"
           "\n   Total network flows: %d\n", total_packs,tcp_counter,udp_counter,tcp_Bcounter,udp_Bcounter,tcp_flows_counter,udp_flows_counter,list_counter);
}

//Function for searching if current protocol matches with any high-level well known protocol
//Check first for source port and then for destination port
void
find_protocol(uint16_t src_port, uint16_t dst_port)
{
    switch (src_port)
    {
    case 80:
        printf("    Protocol: HTTP\n");
        break;
    case 20:
        printf("    Protocol: FTP\n");
        break;
    case 25:
        printf("    Protocol: SMTP\n");        
        break;
    case 23: 
        printf("    Protocol: Telnet\n");        
        break;
    case 53:
        printf("    Protocol: DNS\n");
    case 8443:
        printf("    Protocol: SW Soft Plesk\n");
    default:
        switch (dst_port)
        {
            case 80:
                printf("    Protocol: HTTP\n");
            break;
            case 20:
                printf("    Protocol: FTP\n");
            break;
            case 25:
                printf("    Protocol: SMTP\n");        
            break;
            case 23: 
                printf("    Protocol: Telnet\n");        
            break;
            case 53:
                printf("    Protocol: DNS\n");
            case 8443:
                printf("    Protocol: SW Soft Plesk\n");
            default:
                printf("    Could not match a high level protocol\n");
            break;
        }
        break;
    }
}
void
usage(void)
{
	printf(
        "\n"
        "usage:\n"
        "\t./monitor \n"
        "Options:\n"
        "-r, Packet capture file name (e.g., test.pcap)\n"
        "-h, Help message\n\n"
        );
    exit(1);
}