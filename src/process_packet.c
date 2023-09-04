#include "process_packet.h"

void print_packet_summary(unsigned char *buffer, int len)
{
    struct iphdr *ip_header;
    unsigned short ip_header_len;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct sockaddr_in source;
    struct sockaddr_in dest;
    
    ++packet_id;
    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip_header_len = ip_header->ihl * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    switch (ip_header->protocol)
    {
    case 1: /* ICMP Protocol */
        printf("[%d] (ICMP) packet from (%s) to (%s)", packet_id, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
        fwrite(buffer, 1, PACKET_MAX_LEN, temp_file);
        break;
    case 6: /* TCP Protocol */
        tcp_header = (struct tcphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));
        printf("[%d] (TCP) packet from (%s:%d) to (%s:%d)", packet_id, inet_ntoa(source.sin_addr), ntohs(tcp_header->source), inet_ntoa(dest.sin_addr), ntohs(tcp_header->dest));
        fwrite(buffer, 1, PACKET_MAX_LEN, temp_file);
        break;
    case 17: /* UDP Protocol */
        udp_header = (struct udphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));
        printf("[%d] (UDP) packet from (%s:%d) to (%s:%d)", packet_id, inet_ntoa(source.sin_addr), ntohs(udp_header->source), inet_ntoa(dest.sin_addr), ntohs(udp_header->dest));
        fwrite(buffer, 1, PACKET_MAX_LEN, temp_file);
        break;
    }
}

static void print_ethernet_header(unsigned char *buffer, int len, FILE *file)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;

    fprintf(file, "\nEthernet Header\n");
    fprintf(file, "\t\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(file, "\t\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(file, "\t\t|-Protocol : %d\n", eth->h_proto);
}

static void print_ip_header(unsigned char *buffer, int len, FILE *file)
{
    struct iphdr *ip_header;
    struct sockaddr_in source;
    struct sockaddr_in dest;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    fprintf(file, "\nIP Header\n");
    fprintf(file, "\t\t|-Version                 : %d\n", (unsigned int)ip_header->version);
    fprintf(file, "\t\t|-Internet Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)ip_header->ihl, ((unsigned int)(ip_header->ihl)) * 4);
    fprintf(file, "\t\t|-Type Of Service         : %d\n", (unsigned int)ip_header->tos);
    fprintf(file, "\t\t|-Total Length            : %d  Bytes(size of Packet)\n", ntohs(ip_header->tot_len));
    fprintf(file, "\t\t|-Identification          : %d\n", ntohs(ip_header->id));
    fprintf(file, "\t\t|-Time To Live            : %d\n", (unsigned int)ip_header->ttl);
    fprintf(file, "\t\t|-Protocol                : %d\n", (unsigned int)ip_header->protocol);
    fprintf(file, "\t\t|-Header Checksum         : %d\n", ntohs(ip_header->check));
    fprintf(file, "\t\t|-Source IP               : %s\n", inet_ntoa(source.sin_addr));
    fprintf(file, "\t\t|-Destination IP          : %s\n", inet_ntoa(dest.sin_addr));
}

static void print_packet_data(unsigned char *data, int len, FILE *file)
{
    int i;

    fprintf(file, " %.2X ", data[0]);
    for (i = 1; i < len; i++)
    {
        if (i % 16 == 0)
        {
            fprintf(file, "\n");
        }
        fprintf(file, " %.2X ", data[i]);
    }
}

static void print_tcp_packet(unsigned char *buffer, int len, FILE *file)
{
    struct iphdr *ip_header;
    unsigned short ip_header_len;
    struct tcphdr *tcp_header;
    unsigned short headers_len;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip_header_len = ip_header->ihl * 4;
    tcp_header = (struct tcphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));

    fprintf(file, "\n\n***********************TCP Packet*************************\n");
    print_ethernet_header(buffer, len, file);
    print_ip_header(buffer, len, file);

    fprintf(file, "\nTCP Header\n");
    fprintf(file, "\t\t|-Source Port        : %u\n", ntohs(tcp_header->source));
    fprintf(file, "\t\t|-Destination Port   : %u\n", ntohs(tcp_header->dest));
    fprintf(file, "\t\t|-Sequence Number    : %u\n", ntohl(tcp_header->seq));
    fprintf(file, "\t\t|-Acknowledge Number : %u\n", ntohl(tcp_header->ack_seq));
    fprintf(file, "\t\t|-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcp_header->doff, (unsigned int)tcp_header->doff * 4);
    fprintf(file, "\t\t|----------Flags----------");
    fprintf(file, "\t\t\t\t|-Urgent Flag          : %d\n", (unsigned int)tcp_header->urg);
    fprintf(file, "\t\t\t\t|-Acknowledgement Flag : %d\n", (unsigned int)tcp_header->ack);
    fprintf(file, "\t\t\t\t|-Push Flag            : %d\n", (unsigned int)tcp_header->psh);
    fprintf(file, "\t\t\t\t|-Reset Flag           : %d\n", (unsigned int)tcp_header->rst);
    fprintf(file, "\t\t\t\t|-Synchronise Flag     : %d\n", (unsigned int)tcp_header->syn);
    fprintf(file, "\t\t\t\t|-Finish Flag          : %d\n", (unsigned int)tcp_header->fin);
    fprintf(file, "\t\t|-Window size        : %d\n", ntohs(tcp_header->window));
    fprintf(file, "\t\t|-Checksum           : %d\n", ntohs(tcp_header->check));
    fprintf(file, "\t\t|-Urgent Pointer     : %d\n", tcp_header->urg_ptr);

    fprintf(file, "\nData\n");
    headers_len = ip_header_len + tcp_header->doff * 4;
    print_packet_data(buffer + headers_len, len - headers_len, file);
    fprintf(file, "\n**********************************************************\n");
}

static void print_udp_packet(unsigned char *buffer, int len, FILE *file)
{
    struct iphdr *ip_header;
    unsigned short ip_header_len;
    struct udphdr *udp_header;
    unsigned short headers_len;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip_header_len = ip_header->ihl * 4;
    udp_header = (struct udphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));

    fprintf(file, "\n\n***********************UDP Packet*************************\n");
    print_ethernet_header(buffer, len, file);
    print_ip_header(buffer, len, file);

    fprintf(file, "\nUDP Header\n");
    fprintf(file, "\t\t|-Source Port      : %d\n", ntohs(udp_header->source));
    fprintf(file, "\t\t|-Destination Port : %d\n", ntohs(udp_header->dest));
    fprintf(file, "\t\t|-UDP Length       : %d\n", ntohs(udp_header->len));
    fprintf(file, "\t\t|-UDP Checksum     : %d\n", ntohs(udp_header->check));

    fprintf(file, "Data\n");
    headers_len = ip_header_len + sizeof(udp_header);
    print_packet_data(buffer + headers_len, len - headers_len, file);
    fprintf(file, "\n**********************************************************\n");
}

static void print_icmp_packet(unsigned char *buffer, int len, FILE *file)
{
    struct iphdr *ip_header;
    unsigned short ip_header_len;
    struct icmphdr *icmp_header;
    unsigned short headers_len;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip_header_len = ip_header->ihl * 4;
    icmp_header = (struct icmphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));

    fprintf(file, "\n\n***********************ICMP Packet*************************\n");
    print_ethernet_header(buffer, len, file);
    print_ip_header(buffer, len, file);

    fprintf(file, "\nICMP Header\n");
    fprintf(file, "\t\t|-Type : %d", (unsigned int)(icmp_header->type));

    if ((unsigned int)(icmp_header->type) == 11)
        fprintf(file, "\t\t(TTL Expired)\n");
    else if ((unsigned int)(icmp_header->type) == ICMP_ECHOREPLY)
        fprintf(file, "\t\t(ICMP Echo Reply)\n");
    fprintf(file, "\t\t|-Code : %d\n", (unsigned int)(icmp_header->code));
    fprintf(file, "\t\t|-Checksum : %d\n", ntohs(icmp_header->checksum));
    fprintf(file, "\t\t|-ID       : %d\n", ntohs(icmp_header->un.echo.id));
    fprintf(file, "\t\t|-Sequence : %d\n", ntohs(icmp_header->un.echo.sequence));

    fprintf(file, "\nData\n");
    headers_len = ip_header_len + sizeof(icmp_header);
    print_packet_data(buffer + headers_len, len - headers_len, file);

    fprintf(file, "\n**********************************************************\n");
}

void print_packet_detailed(unsigned char *buffer, int len, FILE *file)
{
    struct iphdr *ip_header;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    switch (ip_header->protocol)
    {
    case 1: /* ICMP Protocol */
        print_icmp_packet(buffer, len, file);
        break;
    case 6: /* TCP Protocol */
        print_tcp_packet(buffer, len, file);
        break;
    case 17: /* UDP Protocol */
        print_udp_packet(buffer, len, file);
        break;
    }
}