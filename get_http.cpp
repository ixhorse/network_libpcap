#include <pcap.h>
#include <arpa/inet.h>
#include "get_http.h"
#include <string.h>
#include <zlib.h>
#include <iostream>
#include <sys/stat.h> 

using namespace std;


#define get_u_int8_t(X,O)  (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u_int16_t(X,O)  (*(uint16_t *)(((uint8_t *)X) + O))
#define get_u_int32_t(X,O)  (*(uint32_t *)(((uint8_t *)X) + O))
#define get_u_int64_t(X,O)  (*(uint64_t *)(((uint8_t *)X) + O))

#define MAX_FILES 10 //一个网页的元素个数
#define MAX_RESPOND_PACK_NUM 1000 // 响应包的个数
#define MAX_REQ_PACK_NUM 1000 // 请求包的个数
#define MAX_PAYLAOD_LENGTH 5000
#define MAX_RELATIVE_URL_LEN 100
#define MAX_UNCOMPRESSED_DATA_LEN 2000000
#define MAX_SAME_ACK_PACK_CNT 30
#define MAX_SRC_URL_LEN 200
#define MAX_WEBSITE_LEN 100

typedef struct HttpNode
{
    u_int ack;
    u_int seq;
    u_int len;
    char data[10000];
} HttpLNode;

pcap_t *pcap_handle = NULL;//libpcap handle

char s_website[] = "nic.utsz.edu.cn";
//char s_website[] = "host.robots.ox.ac.uk:8080";
static char s_src_addr[20];
static char s_dst_addr[20];
static char s_website_IP_addr[20] = { 0 };
static int s_bIsFinish = 0; // 指定的TCP连接是否结束

static HttpLNode *httpRespondPktList = new HttpLNode[MAX_RESPOND_PACK_NUM];
static HttpLNode *httpRequestPktList = new HttpLNode[MAX_REQ_PACK_NUM];
static int s_http_respond_packet_cnt = 0; // 接收到响应包的个数
static int s_http_request_packet_cnt = 0; // 接收到请求包的个数

void bin_ins_sort(HttpLNode *list, int start, int end, CMP_KEY key)
{
	int i = 0;
    int j = 0;
    if (key == CMP_ACK)	// key is Acknowledge
    {
        for(i=start;i<end;i++)
        {
            for(j=i;j<end;j++)
            {
                if(list[j].ack<list[i].ack)
                {
                    HttpLNode temp=list[i];
                    list[i]=list[j];
                    list[j]=temp;

                }
            }
        }
    }
    else if(key==CMP_SEQ)	// 按序列号进行排序
    {
        for(i=start;i<end;i++)
        {
            for(j=i;j<end;j++)
            {
                if(list[j].seq<list[i].seq)
                {
                        HttpLNode temp=list[i];
                        list[i]=list[j];
                        list[j]=temp;

                }
            }
        }
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
        printf("respond list length : %d\n", s_http_respond_packet_cnt);

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
        printf("\t data length: %d\n", caplen);
        
        if(source_port == 80 && 0 != caplen)
        {
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
                    // printf("***data****\n");
                    // printf("%s", payload);
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
            char temp[MAX_PAYLAOD_LENGTH];
            memset(temp, '\0', MAX_PAYLAOD_LENGTH);
            memcpy(temp, httpRequestPktList[s_http_request_packet_cnt-1].data, httpRequestPktList[s_http_request_packet_cnt-1].len);
            printf("%s\n", temp);
        }
    }      
    packet_number++;
    return;
}

static bool save_file(char* filepath, char* data, int data_len)
{
	FILE* fp = NULL;
	if (NULL == (fp = fopen(filepath, "w+")))//文件方式修改w+
	{
		fprintf(stderr,  "fopen:%s, Line %d in %s\n",  strerror(errno),   __LINE__,  __FILE__);
		return false;
	}
	printf("\n*****创建文件名称成功****\n");
	printf("\n*****待写入的文件的长度为：%d  \n",strlen(data));
	if (0 == fwrite(data, 1, strlen(data), fp))//写入文件信息
	{
		fprintf(stderr,  "fwrite:%s, Line %d in %s\n",   strerror(errno),  __LINE__,  __FILE__);
		fclose(fp);
		return false;
	}
	printf("\n*****文件数据保存成功****\n");
	fclose(fp);
	return true;
}

static int modify_html_src_path(char* html_file, char* website)
{
	FILE* fp = NULL;
	if (NULL == (fp = fopen(html_file, "r")))
	{
		fprintf(stderr,  "fopen:%s, Line %d in %s\n",   strerror(errno),   __LINE__,   __FILE__);
		return -1;
	}

	// get all data and store in the buffer
	fseek(fp, 0, SEEK_END);
	long file_len = ftell(fp);
	rewind(fp);
	char* buffer = new char[file_len + 1];
	if (fread(buffer, 1, file_len, fp) < file_len)
	{
		fprintf(stderr, "fread:%s, Line %d in %s\n",strerror(errno),  __LINE__,  __FILE__);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	// modify path
	char* pSrc = buffer;
	for (;;)
	{
		// search 'src='
		if (NULL == (pSrc = strstr(pSrc, "src=")))
		{
			break; // no 'src=' found
		}
		else
		{
			pSrc += 4;
			char* pSrcEnd1 = NULL;
			char* pSrcEnd2 = NULL;
			char* pSrcEnd = NULL;
			// if the hyperlink end with space ' ' or '>'
			// return the pointer to the first one to appear
			if (NULL == (pSrcEnd1 = strstr(pSrc, ">")) || NULL == (pSrcEnd2  = strstr(pSrc, " ")))
			{
				break; // not found, broken html
			}
			else
			{
				pSrcEnd = (pSrcEnd1 < pSrcEnd2) ? pSrcEnd1 : pSrcEnd2;
				for (; pSrcEnd > pSrc && '/' != *pSrcEnd; pSrcEnd--)
				{
					;
				}
				if (pSrcEnd > pSrc)
				{
					memset(pSrc, '\0', pSrcEnd - pSrc + 1);
				}
			}
		}
	}

	if (NULL == (fp = fopen(html_file, "w+")))
	{
		fprintf(stderr,"fopen:%s, Line %d in %s\n",   strerror(errno),
		        __LINE__,
		        __FILE__);
		return -1;
	}
	for (int i = 0; i < file_len; i++)
	{
		if ('\0' != buffer[i])
		{
			fputc(buffer[i], fp);
		}
		else if ('\0' != buffer[i - 1])
		{
			fputs(website, fp);
		}
	}
	fclose(fp);
	return 0;
}

static int decompress_data(char* Path, int file_len)
{
	gzFile fp = NULL;
	if (NULL == (fp = gzopen(Path, "rb+")))//判断打开是否成功
	{
		fprintf(stderr, "gzopen:%s, Line %d in %s\n",  strerror(errno),   __LINE__,  __FILE__);
		return -1;
	}
	printf("\n*****创建压缩文件成功*****\n");
	char buf[MAX_UNCOMPRESSED_DATA_LEN];
	int unlen = 0;
	while (!gzeof(fp))
	{
		buf[unlen++] = gzgetc(fp);
	}
	gzclose(fp);

	if (0 != unlen)
	{
		FILE* hp = NULL;
		char newFileName[MAX_RELATIVE_URL_LEN];
		memset(newFileName, '\0', MAX_RELATIVE_URL_LEN);
		strncpy(newFileName, Path, strlen(Path) - 3); // 保存为对应的非压缩文件，去掉.gz
		if (NULL == (hp = fopen(newFileName, "w+")))
		{
			fprintf(stderr,  "fopen:%s, Line %d in %s\n",  strerror(errno),   __LINE__,   __FILE__);
			return -1;
		}

		for (int i = 0; i < unlen; i++)//写入非压缩文件
		{
			fputc(buf[i], hp);
		}
		fclose(hp);
	}

	return 0;
}

static int reassemble_data(HttpLNode *httpRespondPktList, int start_idx, int end_idx, char* reassembled_data,  bool* isCompressed)
{
	int reIdx = 0; // the length of reassembled data
	char* pDataStart = NULL;
	char* pStatus = NULL;
	char*pStatus1=NULL;
	pStatus = strstr(httpRespondPktList[start_idx].data, "200");//响应包头成功的状态
	pStatus1= strstr(httpRespondPktList[start_idx].data, "304");//响应包头未修改的状态
	// if ((pStatus==NULL)&&(pStatus1==NULL))
	// {
	// 	printf("\n*************包头响应失败*********************\n");
	// 	return -1;
	// }
    printf("\n********包头响应正常**********\n");
	int ContentLength = 0;//保存内容的长度
	char* pContentLength = NULL;//定位到响应报文的content-length
	//keyu 改
	pContentLength = strstr(httpRespondPktList[start_idx].data, "Content-Length:");
	if (NULL != pContentLength)
	{
		pContentLength += 16;
		char* end = NULL;
		char strContentLen[10];
		memset(strContentLen, '\0', 10);
		end = strchr(pContentLength, '\r');//就是获得内容的长度信息
		strncpy(strContentLen, pContentLength, end - pContentLength);
		ContentLength = atoi(strContentLen);//将字符型转化为整型,就是内容的长度
		//printf("\n*****第一个响应包的内容的长度获取成功！长度为：%d   *****\n",ContentLength);
	}
	else if(NULL == pContentLength)
	{
		printf("\n*****数据包的长度的信息定位失败！*******\n");
	}
	printf("\n*****第一个包的内容的长度获取成功！长度为：%d   *****\n",ContentLength);//ke

	char* pContentEncoding = NULL;
	if (NULL != (pContentEncoding = strstr(httpRespondPktList[start_idx].data,  "Content-Encoding: gzip")))//判断响应报文的格式是否压缩
	{
		*isCompressed = true;
		printf("\n*****数据包采取压缩方式！*****\n");
	}

	if (NULL != (pDataStart = strstr(httpRespondPktList[start_idx].data, "\r\n\r\n")))
	{
		pDataStart += 4; // jump over "\r\n\r\n"定位到数据实体的开始
		int slen = httpRespondPktList[start_idx].len - short(pDataStart - httpRespondPktList[start_idx].data);//ke****
		memcpy(&reassembled_data[reIdx], pDataStart, slen);//slen 就是响应包中实体数据的长度，reassembled_data中放的就是数据的内容
		reIdx += slen;//就是具有相同的ack确认号 的响应包的数据的长度
		printf("\n******第一个包的数据部分长度为：%d*******\n",slen);
	}

	// 合并剩余部分
	for (int i = start_idx + 1; i < end_idx; i++)
	{
		if (httpRespondPktList[i].seq == httpRespondPktList[i - 1].seq + httpRespondPktList[i - 1].len)
		{
			// correct message
			memcpy(&reassembled_data[reIdx], httpRespondPktList[i].data, httpRespondPktList[i].len);
			reIdx += httpRespondPktList[i].len;
			printf("\n*******数据包合并正常********\n");
		}
		else if (httpRespondPktList[i].seq > httpRespondPktList[i - 1].seq
		        && httpRespondPktList[i].seq < httpRespondPktList[i - 1].seq
		                + httpRespondPktList[i - 1].len
		        && httpRespondPktList[i].seq + httpRespondPktList[i].len
		                > httpRespondPktList[i - 1].seq + httpRespondPktList[i
		                        - 1].len)
		{
			int newDataOffset = 0;
			newDataOffset = httpRespondPktList[i - 1].seq + httpRespondPktList[i - 1].len - httpRespondPktList[i].seq;
			memcpy(&reassembled_data[reIdx], httpRespondPktList[i].data  + newDataOffset, httpRespondPktList[i].len - newDataOffset);
			reIdx += httpRespondPktList[i].len - newDataOffset;
		}
		else
		{
			cout << "(i-1)SEQ:" << httpRespondPktList[i - 1].seq << endl;
			cout << "(i-1)LEN:" << httpRespondPktList[i - 1].seq << endl;
			cout << "(i)SEQ:" << httpRespondPktList[i - 1].seq << endl;
			cout << "(i)LEN:" << httpRespondPktList[i - 1].seq << endl;
		}
	}
	printf("\n****数据包的长度是:   %d         \n",ContentLength);
	return ContentLength == 0 || ContentLength == reIdx ? reIdx : -1;
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

    bin_ins_sort(httpRespondPktList, 0, s_http_respond_packet_cnt, CMP_ACK);
    bin_ins_sort(httpRequestPktList, 0, s_http_request_packet_cnt, CMP_SEQ);

    char* elemDirName = new char[MAX_WEBSITE_LEN + 10];
	memset(elemDirName, '\0', MAX_WEBSITE_LEN + 10);
	strcat(strcpy(elemDirName, s_website), "_files/");
	mkdir(elemDirName, 0777);//创建了网站的目录

    for (int i = 0; i < s_http_respond_packet_cnt;)//找到相针对同一个请求包的多个响应包，并将其进行排序，以待重组
	{
		int startIdx = i; // 响应链表中包干同意确认号 的序列的起始位置
		int endIdx = i; // 响应链表中包干同意确认号 的序列的结束位置
		unsigned int curAck = httpRespondPktList[i].ack; // 待比较的确认耗
		int nTotalLen = 0; // 包含相同确认号的子序列的长度
		bool bIsCompressed = false; // 数否压缩
		int sub_count=0;//指示下一个响应包的启示位置

		for (; endIdx < s_http_respond_packet_cnt && curAck  == httpRespondPktList[endIdx].ack; endIdx++,sub_count++)
		{
			nTotalLen += httpRespondPktList[endIdx].len;
			printf("\n****************有多个相同的ACK 包******************\n");
		}

		printf("\n********第%d组响应包中有 %d个 相同的数据包*********\n",i,sub_count);
		bin_ins_sort(httpRespondPktList, startIdx, endIdx, CMP_SEQ);//将找到的子响应序列包按序列号进行排序

		char* reasmdData = new char[nTotalLen]; // reassembled data
		int effectiveLen = 0; // the length of reassembled data without http header
		memset(reasmdData, '\0', nTotalLen);
		if (!reasmdData)
		{
			return false;
		}

		reassemble_data(httpRespondPktList, startIdx, endIdx, reasmdData,&bIsCompressed);//还原信息
		//测试reasmdData中是否有数据
		printf("\n********reasmdData中的数据为： %d	\n",strlen(reasmdData));

		int reqIdx = 0;//按照还原的原理去请求链表中搜索对应的请求头
		for (; reqIdx < s_http_request_packet_cnt && curAck != httpRequestPktList[reqIdx].seq + httpRequestPktList[reqIdx].len; reqIdx++)
		{
			;
		}
		if (reqIdx >= s_http_request_packet_cnt)//搜索失败
		{
			i = endIdx;
			printf("\n****没有找到相关的请求包*******\n");
			continue;
		}
		char relativeURL[MAX_RELATIVE_URL_LEN];
		char* rp = relativeURL;//存储请求报文中的URL字段
		char* pHttp = httpRequestPktList[reqIdx].data;
		pHttp += 4; // 定位到Get之后
		for (; ' ' != *pHttp;)
		{
			*rp++ = *pHttp++;
		}
		*rp = '\0';

		printf("\n*******URL字段的长度为：%d \n",strlen(relativeURL));//测试一下长度，<1?
		// 从请求包头信息中获得请求文件的描述信息
		char filename[MAX_RELATIVE_URL_LEN];
		memset(filename, '\0', MAX_RELATIVE_URL_LEN);
		char Path[MAX_RELATIVE_URL_LEN]; // 存储路径
		memset(Path, '\0', MAX_RELATIVE_URL_LEN);
		// the case 'GET /HTTP/1.1' in the first line in request message
		if (strlen(relativeURL) <= 1)//小于1？
		{
			strcat(strcat(filename, s_website), ".html");

			bIsCompressed ? strcat(filename, ".gz") : NULL;
			strcat(Path, filename);
			printf("\n*************** html文件保存成功***************\n");
		}
		// the case like 'GET /image/xxx.gif HTTP/1.1' in first line in request message
		else
		{
			int k = 0;
			for (k = strlen(relativeURL) - 1; k >= 0 && '/' != relativeURL[k]; k--)
			{
				;
			}
			strcat(filename, &relativeURL[k + 1]);
			bIsCompressed ? strcat(filename, ".gz") : NULL;
			strcat(strcat(Path, elemDirName), filename);
		}
		//save_file(Path, reasmdData, effectiveLen);//保存文件
		if (bIsCompressed)
		{
			if (-1 == decompress_data(Path, effectiveLen))
			{
				fprintf(stderr,  "decompress:%s, Line %d in %s\n", strerror(errno),   __LINE__,    __FILE__);
				cout << "could not decompress data!" << endl;
			}
		}
		save_file(Path, reasmdData, effectiveLen);//保存文件
		cout << "Saved File: " << Path << endl;

		i = endIdx;
		delete[] reasmdData;
	}

    char mainHtmlName[MAX_WEBSITE_LEN];
	memset(mainHtmlName, '\0', MAX_WEBSITE_LEN);
	strcat(strcat(mainHtmlName, s_website), ".html");
	if (0 == access(mainHtmlName, F_OK))
	{
		modify_html_src_path(mainHtmlName, elemDirName);
	}

    fclose(fp);

    printf("****************************\n");
    printf("respond length : %d\n", s_http_respond_packet_cnt);
    printf("request length : %d\n", s_http_request_packet_cnt);

    return 0;
}