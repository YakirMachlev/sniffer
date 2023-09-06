#include "control_sniffer.h"

bool stop;
unsigned char *buffer;

void *start_sniffing()
{
    int saddr_len;
    struct sockaddr saddr;
    unsigned int buffer_len;

    pthread_detach(pthread_self());

    stop = false;
    puts("\nStarts sniffing");
    while (!stop)
    {
        pthread_mutex_lock(&mutex);
        saddr_len = sizeof(saddr);
        buffer_len = recvfrom(sock_raw, buffer, PACKET_MAX_LEN, 0, &saddr, (socklen_t *)&saddr_len);
        if (buffer_len < 0)
        {
            puts("Recvfrom error, failed to get packets");
            exit(1);
        }
        print_packet_summary(buffer);
    }

    pthread_exit(NULL);
}

static void stop_sniffing()
{
    puts("\nStops sniffing");
    stop = true;
}

static void inspect_packet()
{
    int32_t id;

    puts("\nInspect packet:");
    id = 1;
    while (id)
    {
        printf("Enter the packet id: ");
        scanf("%d", &id);

        fseek(temp_file, id * PACKET_MAX_LEN, SEEK_SET);
        fread(buffer, 1, PACKET_MAX_LEN, temp_file);

        print_packet_detailed(buffer, strlen((char *)buffer), stdout);
    }
}

static void create_packets_log_file()
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
    fclose(log_file);
    printf("\nCreated the file %s\n", file_name);
}

static void reset_sniffer()
{
    packet_id = 0;
    system("clear");
    fclose(temp_file);
    temp_file = tmpfile();

    puts("Reset sniffer");
}

static void handle_action(char action)
{
    switch (action)
    {
    case 's':
        pthread_create(&sniffer_thread, NULL, start_sniffing, NULL);
        break;
    case 'k':
    case 'b':
        stop_sniffing();
        break;
    case 'i':
        stop_sniffing();
        inspect_packet();
        break;
    case 'd':
        stop_sniffing();
        create_packets_log_file();
        break;
    case 'e':
        stop_sniffing();
        reset_sniffer();
        break;
    default:
        puts("Invalid option");
        break;
    }
}

void *user_actions()
{
    char action;

    pthread_detach(pthread_self());

    action = 0;
    buffer = (unsigned char *)malloc(PACKET_MAX_LEN);
    memset(buffer, 0, PACKET_MAX_LEN);

    while (action != 'b')
    {
        puts("\ns - start listening\nk - stop listening\ni - inspect packet\nd - create log file\ne - erase history\nb - exit the program");
        scanf(" %c", &action);
        handle_action(action);
    }

    free(buffer);
    pthread_exit(NULL);
}