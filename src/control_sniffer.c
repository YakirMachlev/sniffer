#include "control_sniffer.h"

bool stop = false;

void start_sniffing()
{
    int saddr_len;
    struct sockaddr saddr;
    int buffer_len;

    while (!stop)
    {
        saddr_len = sizeof(saddr);
        buffer_len = recvfrom(sock_raw, buffer, PACKET_MAX_LEN, 0, &saddr, (socklen_t *)&saddr_len);
        if (buffer_len < 0)
        {
            puts("Recvfrom error, failed to get packets");
            /* exit(1); */
        }
        else
        {
            puts("hi");
            print_packet_summary(buffer, buffer_len);
        }
    }
}

void inspect_packet()
{
    int32_t id;
    /* something with lock */

    id = 1;
    while (id)
    {
        printf("Enter the packet id: ");
        scanf("%d", &id);

        fseek(temp_file, id * PACKET_MAX_LEN, SEEK_SET);
        fread(buffer, 1, PACKET_MAX_LEN, temp_file);

        print_packet_detailed(buffer, strlen((char *)buffer), stdin);
    }
}

void create_packets_log_file()
{
    char file_name[40];
    FILE *log_file;
    time_t t;
    struct tm tm;
    char date[11];
    char hour[9];

    t = time(NULL);
    tm = *localtime(&t);
    sprintf(date, "%d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    sprintf(hour, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

    sprintf(file_name, "my_sniffer_%s_%s.txt", date, hour);
    log_file = fopen(file_name, "w+");

    rewind(temp_file);
    while (!feof(temp_file))
    {
        fread(buffer, 1, PACKET_MAX_LEN, temp_file);
        print_packet_detailed(buffer, strlen((char *)buffer), log_file);
        temp_file += PACKET_MAX_LEN;
        puts("c");
    }
}

void reset_sniffer()
{
    packet_id = 0;
    system("clear");
    fclose(temp_file);
    temp_file = tmpfile();
}

void handle_action(char action)
{
    switch (action)
    {
    case 's':
        stop = false;
        packet_id = 0;
        start_sniffing();
        break;
    case 'k':
        stop = true;
        break;
    case 'i':
        inspect_packet();
        break;
    case 27: /* ESC */
        break;
    case 'd':
        create_packets_log_file();
        break;
    case 'e':
        reset_sniffer();
        break;
    }
}

void *user_actions()
{
    char action;
    while ((action = getchar()))
    {
        puts("action");
        handle_action(action);
    }

    pthread_exit(NULL);
}