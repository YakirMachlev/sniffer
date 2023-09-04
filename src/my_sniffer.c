#include "process_packet.h"
#include "control_sniffer.h"

FILE *temp_file;
int sock_raw;
unsigned char *buffer;
int packet_id = 0;

static void sniffer()
{
    int sock_raw;
    pthread_t ui_thread;

    buffer = (unsigned char *)malloc(PACKET_MAX_LEN);
    memset(buffer, 0, PACKET_MAX_LEN);
    temp_file = tmpfile();
    if (temp_file == NULL)
        puts("Unable to create the temp file");

    puts("Welcome to my sniffer");
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        perror("Socket Error");
        exit(1);
    }

    start_sniffing();
    /* pthread_create(&ui_thread, NULL, user_actions, NULL);
    pthread_join(ui_thread, NULL); */

    close(sock_raw);
    fclose(temp_file);
    free(buffer);
    puts("Finished");
}

int main()
{
    sniffer();
    return 0;
}