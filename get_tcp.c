#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

struct ether_header
{
    u_int8_t ether_dhost[6];//目的mac
    u_int8_t ether_shost[6];//源
    u_int16_t ether_type;
};
//以太网帧头部

// typedef u_int32_t in_addr_t;
// struct in_addr
// {
//     in_addr_t s_addr;
// };

struct ip_header
{
    #ifdef WORDS_DIGENDIAN
        u_int8_t ip_version: 4,
        ip_header_length: 4;
    #else
        u_int8_t ip_header_length: 4, 
        ip_version: 4;
    #endif
    u_int8_t ip_tos;        //TOS服务质量

    u_int16_t ip_length;    //总长度

    u_int16_t ip_id;        //标识

    u_int16_t ip_off;       //3标志+13偏移

    u_int8_t ip_ttl;        //ttl

    u_int8_t ip_protocol;   //携带数据的协议类型

    u_int16_t ip_checksum;  

    struct in_addr ip_source_address;

    struct in_addr ip_destination_address;
};


struct tcp_header
{
    u_int16_t tcp_source_port;

    u_int16_t tcp_destination_port;

    u_int32_t tcp_sequence;

    u_int32_t tcp_ack;

    #ifdef WORDS_DIGENDIAN
        u_int8_t tcp_offset : 4,
        tcp_reserved : 4;
    
    #else
        u_int8_t tcp_reserved : 4,
        tcp_offset : 4;
    #endif

    u_int8_t tcp_flags;

    u_int16_t tcp_windows;

    u_int16_t tcp_checksum;

    u_int16_t tcp_urgent_pointer;
};


void tcp_protocol_callback(
    u_char *argument,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_content
){
    struct tcp_header *tcp_protocol;

    u_char flags;
    int header_length;
    u_short source_port;
    u_short destination_port;
    u_short windows;
    u_short urgent_pointer;
    u_int sequence;
    u_int ackownledgement;
    u_int16_t checksum;

    tcp_protocol = (struct tcp_header *)(packet_content + 14 + 20);
    source_port = ntohs(tcp_protocol->tcp_source_port);
    destination_port = ntohs(tcp_protocol->tcp_destination_port);
    header_length = tcp_protocol->tcp_offset * 4;
    sequence = ntohl(tcp_protocol->tcp_sequence);
    ackownledgement = ntohl(tcp_protocol->tcp_ack);
    windows = ntohs(tcp_protocol->tcp_windows);
    urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
    flags = tcp_protocol->tcp_flags;
    checksum = ntohs(tcp_protocol->tcp_checksum);

    printf("-------- TCP Protocol (transport layer) -----------\n");
    printf("Source port:%d\n", source_port);
    printf("Destination port:%d\n", destination_port);
    switch(destination_port)
    {
        case 80:
            printf("Http protocol.\n");
            break;
        case 21:
            printf("FTP protocol.\n");
            break;
        case 23:
            printf("TELNET protocol.\n");
            break;
        case 25:
            printf("SMTP protocol.\n");
            break;
        case 110:
            printf("POP3 protocol.\n");
            break;
        default:
            break;
    }
    printf("Sequence number:%u\n", sequence);
    printf("ACK number:%u\n", ackownledgement);
    printf("Header Length:%d\n", header_length);
    printf("Reserved:%d\n", tcp_protocol->tcp_reserved);
    printf("Flags:");
    if(flags & 0x08) printf("PSH ");
    if(flags & 0x10) printf("ACK ");
    if(flags & 0x02) printf("SYN ");
    if(flags & 0x20) printf("URG ");
    if(flags & 0x01) printf("FIN ");
    if(flags & 0x04) printf("RST ");
    printf("\n");
    printf("Checksum: %d\n", checksum);
    printf("Window size:%d\n", windows);
    printf("Urgent pointer:%d\n", urgent_pointer);
}

void ip_protocol_callback(
    u_char *argument,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_content
)
{
    struct ip_header *ip_protocol;
    u_int header_length;
    u_int offset;
    u_char tos;
    u_int16_t checksum;
    
    ip_protocol = (struct ip_header *)(packet_content + 14);//skip ethernet header

    // checksum = ntohs(ip_protocol->ip_checksum);
    // header_length = ip_protocol->ip_header_length * 4;
    // tos = ip_protocol->ip_tos;
    // offset = ntohs(ip_protocol->ip_off);

    // printf("----- IP Protocol (Network Layer) --------\n");
    // printf("IP Version : %d\n", ip_protocol->ip_version);
    // printf("Header length: %d\n", header_length);
    // printf("TOS : %d\n", tos);
    // printf("Identification:%d\n", ntohs(ip_protocol->ip_id));
    // printf("Offset : %d\n", (offset & 0x1fff) * 8);
    // printf("TTL:%d\n", ip_protocol->ip_ttl);
    // printf("Data Protocol : %d\n", ip_protocol->ip_protocol);
    switch(ip_protocol->ip_protocol)
    {
        case 6:
            printf("The transport layer protocol is TCP.\n");
            break;
        case 17:
            printf("The transport layer protocol is UDP.\n");
            break;
        case 1:
            printf("The transport layer protocol is ICMP.\n");
            break;
        default:
            break;
    }
    //printf("Header checksum:%d\n", checksum);
    printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
    printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));

    switch(ip_protocol->ip_protocol)
    {
        case 6:
            tcp_protocol_callback(argument, packet_header, packet_content);
            break;
        default:
            break;
    }
}

void ethernet_protocol_callback(
    u_char *argument,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_content
)
{
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    u_char *mac_string;
    static int packet_number = 1;

    printf("The %d Ethernet packet is captured.\n", packet_number);
    //printf("-------------  Ethernet procotol (Link Layer)  ------------\n");

    ethernet_protocol = (struct ether_header *)packet_content;
    ethernet_type = ntohs(ethernet_protocol->ether_type);

    //printf("%04x\n", ethernet_type);
    switch(ethernet_type)
    {
        case 0x0800:
            printf("The network layer is IP.\n");
            break;
        case 0x0806:
            printf("The network layer is ARP.\n");
            break;
        case 0x0835:
            printf("The network layer is RARP.\n");
            break;
        default:
            break;
    }

    // printf("Mac Source Address is : \n");
    // mac_string = ethernet_protocol->ether_shost;
    // printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
    //     *mac_string, *(mac_string+1), *(mac_string+2),
    //     *(mac_string+3), *(mac_string+4), *(mac_string+5));

    // printf("Mac Destination Address is : \n");
    // mac_string = ethernet_protocol->ether_dhost;
    // printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
    //     *mac_string, *(mac_string+1), *(mac_string+2),
    //     *(mac_string+3), *(mac_string+4), *(mac_string+5));

    switch(ethernet_type)
    {
        case 0x0800:
            ip_protocol_callback(argument, packet_header, packet_content);
            break;
        default:
            break;
    }

    printf("**********************************************************\n");
    packet_number++;
}

int main()
{
    char error_content[PCAP_ERRBUF_SIZE];//error info

    struct pcap_pkthdr protocol_header;//package header

    pcap_t *pcap_handle = NULL;//libpcap handle

    struct bpf_program bpf_filter;//bpf filter rule

    char bpf_filter_string[] = "ip";

    const u_char *packet_content;//packet

    bpf_u_int32 net_ip;

    bpf_u_int32 net_mask;

    char *net_interface;

    net_interface = pcap_lookupdev(error_content);

    if(net_interface == NULL)
    {
        printf("No device.\n");
        return 0;
    }

    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);

    pcap_handle = pcap_open_live(net_interface,
    BUFSIZ,
    1,//混杂模式
    0,//等待时间
    error_content);

    if(pcap_handle == NULL)
    {
        printf("Open live fail.  %s\n", error_content);
        return 0;
    }

    pcap_compile(pcap_handle,
    &bpf_filter,
    bpf_filter_string,
    0,
    net_ip);

    pcap_setfilter(pcap_handle, &bpf_filter);

    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return;

    pcap_loop(pcap_handle, -1, ethernet_protocol_callback, NULL);
    
    if(pcap_handle != NULL)
        pcap_close(pcap_handle);

    return 0;
}