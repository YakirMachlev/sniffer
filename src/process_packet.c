#include "process_packet.h"

int total = 0;
struct sockaddr_in source, dest;

void process_packet(unsigned char *buffer, int len)
{
    struct iphdr *ip_header = (struct iphdr *)buffer;
    ++total;
    switch (ip_header->protocol)
    {
    case 1: /* ICMP Protocol */
        print_icmp_packet(buffer, len);
        break;
    case 6: /* TCP Protocol */
        print_tcp_packet(buffer, len);
        break;
    case 17: /* UDP Protocol */
        print_udp_packet(buffer, len);
        break;
    }
}

void print_ethernet_header(unsigned char *buffer, int len)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;

    fprintf(logfile, "\nEthernet Header\n");
    fprintf(logfile, "\t\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logfile, "\t\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logfile, "\t\t|-Protocol : %d\n", eth->h_proto);
}

void print_ip_header(unsigned char *buffer, int len)
{
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    fprintf(logfile, "\nIP Header\n");
    fprintf(logfile, "\t\t|-Version                 : %d\n", (unsigned int)ip_header->version);
    fprintf(logfile, "\t\t|-Internet Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)ip_header->ihl, ((unsigned int)(ip_header->ihl)) * 4);
    fprintf(logfile, "\t\t|-Type Of Service         : %d\n", (unsigned int)ip_header->tos);
    fprintf(logfile, "\t\t|-Total Length            : %d  Bytes(size of Packet)\n", ntohs(ip_header->tot_len));
    fprintf(logfile, "\t\t|-Identification          : %d\n", ntohs(ip_header->id));
    fprintf(logfile, "\t\t|-Time To Live            : %d\n", (unsigned int)ip_header->ttl);
    fprintf(logfile, "\t\t|-Protocol                : %d\n", (unsigned int)ip_header->protocol);
    fprintf(logfile, "\t\t|-Header Checksum         : %d\n", ntohs(ip_header->check));
    fprintf(logfile, "\t\t|-Source IP               : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, "\t\t|-Destination IP          : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char *buffer, int len)
{
    struct iphdr *ip_header;
    unsigned short ip_header_len;
    struct tcphdr *tcp_header;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip_header_len = ip_header->ihl * 4;
    tcp_header = (struct tcphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));

    fprintf(logfile, "\n\n***********************TCP Packet*************************\n");
    print_ethernet_header(buffer, len);
    print_ip_header(buffer, len);

    fprintf(logfile, "\n");
    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "\t\t|-Source Port        : %u\n", ntohs(tcp_header->source));
    fprintf(logfile, "\t\t|-Destination Port   : %u\n", ntohs(tcp_header->dest));
    fprintf(logfile, "\t\t|-Sequence Number    : %u\n", ntohl(tcp_header->seq));
    fprintf(logfile, "\t\t|-Acknowledge Number : %u\n", ntohl(tcp_header->ack_seq));
    fprintf(logfile, "\t\t|-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcp_header->doff, (unsigned int)tcp_header->doff * 4);
    fprintf(logfile, "\t\t|----------Flags----------");
    fprintf(logfile, "\t\t\t\t|-Urgent Flag          : %d\n", (unsigned int)tcp_header->urg);
    fprintf(logfile, "\t\t\t\t|-Acknowledgement Flag : %d\n", (unsigned int)tcp_header->ack);
    fprintf(logfile, "\t\t\t\t|-Push Flag            : %d\n", (unsigned int)tcp_header->psh);
    fprintf(logfile, "\t\t\t\t|-Reset Flag           : %d\n", (unsigned int)tcp_header->rst);
    fprintf(logfile, "\t\t\t\t|-Synchronise Flag     : %d\n", (unsigned int)tcp_header->syn);
    fprintf(logfile, "\t\t\t\t|-Finish Flag          : %d\n", (unsigned int)tcp_header->fin);
    fprintf(logfile, "\t\t|-Window size        : %d\n", ntohs(tcp_header->window));
    fprintf(logfile, "\t\t|-Checksum           : %d\n", ntohs(tcp_header->check));
    fprintf(logfile, "\t\t|-Urgent Pointer     : %d\n", tcp_header->urg_ptr);

    fprintf(logfile, "\nData\n");
    print_data(buffer + ip_header_len + tcp_header->doff * 4, (len - tcp_header->doff * 4 - ip_header_len));
    fprintf(logfile, "\n**********************************************************\n");
}

void print_udp_packet(unsigned char *buffer, int len)
{
    struct iphdr *ip_header;
    unsigned short ip_header_len;
    struct udphdr *udp_header;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip_header_len = ip_header->ihl * 4;
    udp_header = (struct udphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));

    fprintf(logfile, "\n\n***********************UDP Packet*************************\n");
    print_ethernet_header(buffer, len);
    print_ip_header(buffer, len);

    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, "\t\t|-Source Port      : %d\n", ntohs(udp_header->source));
    fprintf(logfile, "\t\t|-Destination Port : %d\n", ntohs(udp_header->dest));
    fprintf(logfile, "\t\t|-UDP Length       : %d\n", ntohs(udp_header->len));
    fprintf(logfile, "\t\t|-UDP Checksum     : %d\n", ntohs(udp_header->check));

    fprintf(logfile, "Data\n");
    print_data(buffer + ip_header_len + sizeof(udp_header), (len - sizeof(udp_header) - ip_header_len));
    fprintf(logfile, "\n**********************************************************\n");
}

void print_icmp_packet(unsigned char *buffer, int len)
{
    struct iphdr *ip_header;
    unsigned short ip_header_len;
    struct icmphdr *icmp_header;

    ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip_header_len = ip_header->ihl * 4;
    icmp_header = (struct icmphdr *)(buffer + ip_header_len + sizeof(struct ethhdr));

    fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");
    print_ethernet_header(buffer, len);
    print_ip_header(buffer, len);

    fprintf(logfile, "\n");

    fprintf(logfile, "ICMP Header\n");
    fprintf(logfile, "\t\t|-Type : %d", (unsigned int)(icmp_header->type));

    if ((unsigned int)(icmp_header->type) == 11)
        fprintf(logfile, "\t\t(TTL Expired)\n");
    else if ((unsigned int)(icmp_header->type) == ICMP_ECHOREPLY)
        fprintf(logfile, "\t\t(ICMP Echo Reply)\n");
    fprintf(logfile, "\t\t|-Code : %d\n", (unsigned int)(icmp_header->code));
    fprintf(logfile, "\t\t|-Checksum : %d\n", ntohs(icmp_header->checksum));
    /*     fprintf(logfile, "\t\t|-ID       : %d\n", ntohs(icmph->id));
        fprintf(logfile, "\t\t|-Sequence : %d\n", ntohs(icmph->sequence)); */
    fprintf(logfile, "\n");

    fprintf(logfile, "\nData\n");
    print_data(buffer + ip_header_len + sizeof(icmp_header), (len - sizeof(icmp_header) - ip_header_len));

    fprintf(logfile, "\n**********************************************************\n");
}

void print_data(unsigned char *data, int len)
{
    int i;

    fprintf(logfile, " %.2X ", data[0]);
    for (i = 1; i < len; i++)
    {
        if (i % 16 == 0)
        {
            fprintf(logfile, "\n");
        }
        fprintf(logfile, " %.2X ", data[i]);
    }
}

/* void print_data(unsigned char *data, int size)
{
    int i;
    int j;
    for (i = 0; i < size; i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            fprintf(logfile, "         ");
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(logfile, "%c", (unsigned char)data[j]);

                else
                    fprintf(logfile, ".");
            }
            fprintf(logfile, "\n");
        }

        if (i % 16 == 0)
            fprintf(logfile, "   ");
        fprintf(logfile, " %02X", (unsigned int)data[i]);

        if (i == size - 1)
        {
            for (j = 0; j < 15 - i % 16; j++)
                fprintf(logfile, "   ");

            fprintf(logfile, "         ");

            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(logfile, "%c", (unsigned char)data[j]);
                else
                    fprintf(logfile, ".");
            }
            fprintf(logfile, "\n");
        }
    }
} */