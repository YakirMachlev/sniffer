#include "process_packet.h"
#include "control_sniffer.h"

FILE *temp_file;
int sock_raw;
int packet_id = 0;
pthread_t sniffer_thread;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void sniffer()
{
    int sock_raw;
    pthread_t ui_thread;

    temp_file = tmpfile();
    if (temp_file == NULL)
    {
        puts("Unable to create the temp file");
    }

    puts("Welcome to my sniffer");

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    /* setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, "eth0", strlen("eth0")); */
    if (sock_raw < 0)
    {
        perror("Socket Error");
        exit(1);
    }

    pthread_create(&ui_thread, NULL, user_actions, NULL);
    pthread_join(ui_thread, NULL);

    close(sock_raw);
    fclose(temp_file);
    puts("Finished");
}

int main()
{
    sniffer();
    return 0;
}