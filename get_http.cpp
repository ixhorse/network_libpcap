#include <pcap.h>
#include <arpa/inet.h>
#include "get_http.h"
#include <string.h>


#define get_u_int8_t(X,O)  (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u_int16_t(X,O)  (*(uint16_t *)(((uint8_t *)X) + O))
#define get_u_int32_t(X,O)  (*(uint32_t *)(((uint8_t *)X) + O))
#define get_u_int64_t(X,O)  (*(uint64_t *)(((uint8_t *)X) + O))

#define MAX_FILES 10 //一个网页的元素个数
#define MAX_RESPOND_PACK_NUM 500 // 响应包的个数
#define MAX_REQ_PACK_NUM 500 // 请求包的个数

typedef struct HttpNode
{
    u_int ack;
    u_int seq;
    u_int len;
    char data[5000];
} HttpLNode;

pcap_t *pcap_handle = NULL;//libpcap handle

char s_website[] = "nic.utsz.edu.cn";
static char s_src_addr[20];
static char s_dst_addr[20];
static char s_website_IP_addr[20] = { 0 };
static int s_bIsFinish = 0; // 指定的TCP连接是否结束

static HttpLNode *httpRespondPktList = new HttpLNode[MAX_RESPOND_PACK_NUM];
static HttpLNode *httpRequestPktList = new HttpLNode[MAX_REQ_PACK_NUM];
static int s_http_respond_packet_cnt = 0; // 接收到响应包的个数
static int s_http_request_packet_cnt = 0; // 接收到请求包的个数

void ethernet_protocol_callback(
    u_char *argument,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_content
)
{
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    struct ip_header *ip_protocol;
    struct tcp_header *tcp_protocol;
    static int packet_number = 1;

    u_char flags;
    u_short source_port;
    u_short destination_port;
    u_int sequence;
    u_int ackownledgement;

    u_int32_t offset, caplen;
    int i;
    char *payload;
    HttpLNode hp;
    char chHost[50];

    ethernet_protocol = (struct ether_header *)packet_content;
    ethernet_type = ntohs(ethernet_protocol->ether_type);
    if(ethernet_type != 0x0800)
    {
        packet_number++;
        return;
    }

    ip_protocol = (struct ip_header *)(packet_content + 14);//skip ethernet header
    if(ip_protocol->ip_protocol != 6)
        return;

    tcp_protocol = (struct tcp_header *)(packet_content + 14 + 20);
    source_port = ntohs(tcp_protocol->tcp_source_port);
    destination_port = ntohs(tcp_protocol->tcp_destination_port);
    sequence = ntohl(tcp_protocol->tcp_sequence);
    ackownledgement = ntohl(tcp_protocol->tcp_ack);
    flags = tcp_protocol->tcp_flags;

    if(destination_port == 80 || source_port == 80)
    {
        printf("--------------------------------------------\n");
        strcpy(s_src_addr, inet_ntoa(ip_protocol->ip_source_address));
        strcpy(s_dst_addr, inet_ntoa(ip_protocol->ip_destination_address));
        printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
        printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));

        printf("Sequence number:%u\n", sequence);
        printf("ACK number:%u\n", ackownledgement);
        printf("Flags:");
        if(flags & 0x08) printf("PSH ");
        if(flags & 0x10) printf("ACK ");
        if(flags & 0x02) printf("SYN ");
        if(flags & 0x20) printf("URG ");
        if(flags & 0x01) printf("FIN ");
        if(flags & 0x04) printf("RST ");
        printf("\n");
        printf("respond length : %d\n", s_http_respond_packet_cnt);

        if (strlen(s_website_IP_addr) != 0 && strcmp(s_src_addr, s_website_IP_addr) && (flags & 0x01))//TCP连接是否结束
        {
            s_bIsFinish = 1;
            printf("****************************\n");
            pcap_breakloop(pcap_handle);
            return;
        }

        offset = 14 + 20 + (tcp_protocol->tcp_offset << 2);
        caplen = packet_header->caplen - offset;
        payload = (char *)packet_content + offset;
        
        if(source_port == 80 && 0 != caplen)
        {
            // printf("\t data length: %d\n", caplen);
            // for(i=0; i<caplen; i++)
            // {
            //     if(get_u_int16_t(payload, i) == ntohs(0x0d0a) &&
            //         get_u_int16_t(payload, i+4) == ntohs(0x0d0a))
            //     {
            //         offset += i+4;
            //         break;
            //     } 
            // }
            for (i = 0; i < s_http_request_packet_cnt; i++)
            {
                if (httpRequestPktList[i].seq
                        + httpRequestPktList[i].len == ackownledgement)
                {
                    HttpLNode hp;
                    hp.ack = ackownledgement;
                    hp.seq = sequence;
                    hp.len = caplen;
                    memcpy(hp.data, payload, caplen);
                    httpRespondPktList[s_http_respond_packet_cnt++] = hp;//添加节点到响应链表中
                }
            }
            //fputs(payload, fp);
        }

        if(destination_port == 80 && caplen > 5)
        {
            char *pHttp = payload;
            if (*payload != 'G' || *(payload + 1) != 'E' || *(payload + 2) != 'T')
                return;

            for (; (*pHttp) != 'H' || *(pHttp + 1) != 'o' || *(pHttp + 2) != 's' || *(pHttp + 3) != 't'; pHttp++)//定位倒host,
            {
                ;
            }
            pHttp += 6;
            char *p = chHost; //保存服务器的地址信息
            while (*(pHttp) != 0x0d)
            {
                *p++ = *pHttp++;
            }
            *p = '\0';
            if (0 == strcmp(chHost, s_website))//比较请求到的网址信息和设置的网址是否一致
            {
                strcpy(s_website_IP_addr, s_dst_addr);
            }
            hp.ack = ackownledgement;
            hp.seq = sequence;
            hp.len = caplen;
            memcpy(hp.data, payload, caplen);
            httpRequestPktList[s_http_request_packet_cnt++] = hp;//添加节点到请求链表中
        }
    }      
    packet_number++;
    return;
}

int main()
{
    char error_content[PCAP_ERRBUF_SIZE];//error info
    struct pcap_pkthdr protocol_header;//package header

    struct bpf_program bpf_filter;//bpf filter rule
    char bpf_filter_string[] = "ip";
    const u_char *packet_content;//packet
    bpf_u_int32 net_ip;
    bpf_u_int32 net_mask;
    char *net_interface;

    net_interface = pcap_lookupdev(error_content);

    FILE *fp = fopen("a.txt", "w+");
	memset(httpRespondPktList, '\0', sizeof(HttpLNode) * MAX_RESPOND_PACK_NUM);
	memset(httpRequestPktList, '\0', sizeof(HttpLNode) * MAX_REQ_PACK_NUM);

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
        return 0;
    
    pcap_loop(pcap_handle, 
        -1, //num
        ethernet_protocol_callback, 
        NULL);//para
    
    if(pcap_handle != NULL)
        pcap_close(pcap_handle);


    for(int i=0; i<s_http_respond_packet_cnt; i++)
    {
        int offset = 0;
        char *payload = httpRespondPktList[i].data;
        if(*payload == 'H' && *(payload+1) == 'T' && *(payload+2) == 'T' && *(payload+3) == 'P')
            for(int j=0; i<httpRespondPktList[i].len; j++)
            {
                if(get_u_int16_t(payload, j) == ntohs(0x0d0a) &&
                    get_u_int16_t(payload, j+4) == ntohs(0x0d0a))
                {
                    offset += j+4;
                    break;
                } 
            }
        char temp[] = "\n************************************************************\n";
        fputs(temp, fp);
        fputs(httpRespondPktList[i].data+offset, fp);
    }
    fclose(fp);

    printf("****************************\n");
    printf("respond length : %d\n", s_http_respond_packet_cnt);

    return 0;
}