#include "process_packet.h"

FILE *logfile;

static void sniffer()
{
    int buffer_len;
    int sock_raw;
    struct sockaddr saddr;
    int saddr_len;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    logfile = fopen("log.txt", "w");
    if (logfile == NULL)
        printf("Couldn't create the log file");
    
    printf("Starting...\n");
    /* sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); */
    sock_raw = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        printf("Socket Error\n");
        exit(1);
    }
    while (1)
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
    close(sock_raw);
    printf("Finished");
}

int main()
{
    sniffer();
    return 0;
}