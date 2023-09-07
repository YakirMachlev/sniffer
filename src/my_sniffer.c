#include "process_packet.h"
#include "control_sniffer.h"

FILE *temp_file;
int sock_raw;
int packet_id = 0;
pthread_t sniffer_thread;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void sniffer()
{
    pthread_t ui_thread;

    temp_file = tmpfile();
    if (temp_file == NULL)
    {
        puts("Unable to create the temp file");
    }

    puts("Welcome to my sniffer");
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        perror("Socket Error");
        exit(1);
    }

    /* buffer = (unsigned char *)malloc(PACKET_MAX_LEN);
    while (true)
    {
        buffer_len = recvfrom(sock_raw, buffer, PACKET_MAX_LEN, 0, NULL, NULL);
        if (buffer_len < 0)
        {
            puts("Recvfrom error, failed to get packets");
            exit(1);
        }
        print_packet_summary(buffer);
    }
    free(buffer); */
    user_actions();

    close(sock_raw);
    fclose(temp_file);
    puts("Finished");
}

int main()
{
    sniffer();
    return 0;
}