#include "control_sniffer.h"

void start_sniffing()
{
    int saddr_len;
    struct sockaddr saddr;
    int buffer_len;

    while (!stop)
    {
        saddr_len = sizeof(saddr);
        buffer_len = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (buffer_len < 0)
        {
            printf("Recvfrom error, failed to get packets\n");
            exit(1);
        }
        process_packet(buffer, buffer_len);
    }
}