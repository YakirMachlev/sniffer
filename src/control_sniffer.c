#include "control_sniffer.h"

bool stop;
unsigned char *buffer;

void *start_sniffing()
{
    uint32_t buffer_len;

    pthread_detach(pthread_self());

    stop = false;
    puts("\nStarts sniffing");
    while (!stop)
    {
        buffer_len = recvfrom(sock_raw, buffer, PACKET_MAX_LEN, 0, NULL, NULL);
        if (buffer_len < 0)
        {
            puts("Recvfrom error, failed to get packets");
            exit(1);
        }
        print_packet_summary(buffer, buffer_len);
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
    uint32_t buffer_len;

    puts("\nInspect packet:");

    printf("Enter the packet id (0 to stop): ");
    scanf("%d", &id);
    while (id)
    {
        if (id > 0 && id <= packet_id)
        {
            fseek(temp_file, (id - 1) * (PACKET_LEN_SIZE + PACKET_MAX_LEN), SEEK_SET);
            fread(&buffer_len, PACKET_LEN_SIZE, 1, temp_file);
            fread(buffer, PACKET_MAX_LEN, 1, temp_file);
            print_packet_detailed(buffer, buffer_len, stdout);            
        }
        else
        {
            puts("There is no packet with the entered id\n");
        }
        printf("Enter the packet id (0 to stop): ");
        scanf("%d", &id);
    }
    puts("Inspect finished");
}

static void create_packets_log_file()
{
    uint32_t buffer_len;
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
        fread(&buffer_len, PACKET_LEN_SIZE, 1, temp_file);
        fread(buffer, PACKET_MAX_LEN, 1, temp_file);
        print_packet_detailed(buffer, buffer_len, log_file);
    }
    fclose(log_file);
    printf("Created the file %s\n", file_name);
}

static void reset_sniffer()
{
    packet_id = 0;
    system("clear");

    fseek(temp_file, 0, SEEK_CUR);
    fclose(temp_file);
    temp_file = tmpfile();
    if (temp_file == NULL)
    {
        puts("Unable to create the temp file");
    }

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

void user_actions()
{
    char action;

    buffer = (unsigned char *)malloc(PACKET_MAX_LEN);
    action = 0;
    while (action != 'b')
    {
        puts("\ns - start listening\nk - stop listening\ni - inspect packet\nd - create log file\ne - erase history\nb - exit the program");
        scanf(" %c", &action);
        handle_action(action);
    }

    free(buffer);
}