#include <stdio.h>


struct ether_header
{
    u_int8_t ether_dhost[6];//目的mac
    u_int8_t ether_shost[6];//源
    u_int16_t ether_type;
};

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