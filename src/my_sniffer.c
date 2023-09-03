#include "process_packet.h"
#include "ui.h"

FILE *logfile;
int sock_raw;
bool stop;

static void sniffer()
{
    int sock_raw;
    pthread_t ui_thread;
    unsigned char *buffer;

    buffer = (unsigned char *)malloc(sizeof(char) * 65536);
    logfile = fopen("log.txt", "w");
    if (logfile == NULL)
        printf("Couldn't create the log file");
    
    printf("Starting...\n");
    sock_raw = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {
        perror("Socket Error");
        exit(1);
    }
    pthread_create(&ui_thread, NULL, user_actions, NULL);
    pthread_join(ui_thread, NULL);

    close(sock_raw);
    fclose(logfile);
    free(buffer);
    printf("Finished");
}

int main()
{
    sniffer();
    return 0;
}