#include <pcap.h>
#include <stdio.h>

struct ether_header
{
    u_int8_t ether_dhost[6];//目的mac
    u_int8_t ether_shost[6];//源
    u_int16_t ether_type;
};
//以太网帧头部

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

    printf("***************\n");
    printf("The %d Ethernet packet is captured.\n", packet_number);
    printf("-----  Ethernet procotol (Link Layer)  ----\n");

    ethernet_protocol = (struct ether_header *)packet_content;
    ethernet_type = ntohs(ethernet_protocol->ether_type);

    printf("%04x\n", ethernet_type);
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

    printf("Mac Source Address is : \n");
    mac_string = ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
        *mac_string, *(mac_string+1), *(mac_string+2),
        *(mac_string+3), *(mac_string+4), *(mac_string+5));

    printf("Mac Destination Address is : \n");
    mac_string = ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
        *mac_string, *(mac_string+1), *(mac_string+2),
        *(mac_string+3), *(mac_string+4), *(mac_string+5));

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

    pcap_loop(pcap_handle, 10, ethernet_protocol_callback, NULL);
    
    if(pcap_handle != NULL)
        pcap_close(pcap_handle);

    return 0;
}