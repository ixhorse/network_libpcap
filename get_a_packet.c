#include <pcap.h>
#include <stdio.h>

int main()
{
    char error_content[PCAP_ERRBUF_SIZE];//error info

    struct pcap_pkthdr protocol_header;//package header

    pcap_t *pcap_handle = NULL;//libpcap handle

    struct bpf_program bpf_filter;//bpf filter rule

    char bpf_filter_string[] = "";

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

    packet_content = pcap_next(pcap_handle, &protocol_header);//cap

    printf("Capture a package from : %s\n", net_interface);

    printf("The package length is %d\n", protocol_header.len);
    
    if(pcap_handle != NULL)
        pcap_close(pcap_handle);

    return 0;
}