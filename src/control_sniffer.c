#include "control_sniffer.h"

bool stop;
unsigned char *buffer;

/**
 * @brief starts sniffing packets and writes a summary of each packet
 * 
 */
static void *control_sniffer_start()
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

/**
 * @brief stops the sniffing process
 * 
 */
static void control_sniffer_stop()
{
    puts("\nStops sniffing");
    stop = true;
}

/**
 * @brief allows the user too get detailed information about
 * each packet that was sniffed
 * 
 */
static void control_sniffer_inspect_packet()
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

/**
 * @brief created a log file that contains a detailed description of the
 * sniffed packets
 * 
 */
static void control_sniffer_create_packets_log_file()
{
    uint32_t buffer_len;
    char file_name[40];
    FILE *log_file;
    time_t t;
    struct tm tm;
    char date[11];
    char hour[9];
    bool empty_file;

    t = time(NULL);
    tm = *localtime(&t);
    sprintf(date, "%d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    sprintf(hour, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

    sprintf(file_name, "my_sniffer_%s_%s.txt", date, hour);
    log_file = fopen(file_name, "w+");

    fseek(temp_file, 0, SEEK_END);
    empty_file = ftell(temp_file) == 0;
    if (!empty_file)
    {
        rewind(temp_file);
        while (!feof(temp_file))
        {
            fread(&buffer_len, PACKET_LEN_SIZE, 1, temp_file);
            fread(buffer, PACKET_MAX_LEN, 1, temp_file);
            print_packet_detailed(buffer, buffer_len, log_file);
        }        
    }
    fclose(log_file);
    printf("Created the file %s\n", file_name);
}

/**
 * @brief resets the sniffer
 * 
 */
static void control_sniffer_reset()
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

/**
 * @brief calls a function according to the user input
 * 
 * @param action the user action
 */
static void control_sniffer_handle_action(char action)
{
    switch (action)
    {
    case 's':
        pthread_create(&sniffer_thread, NULL, control_sniffer_start, NULL);
        break;
    case 'k':
    case 'b':
        control_sniffer_stop();
        break;
    case 'i':
        control_sniffer_stop();
        control_sniffer_inspect_packet();
        break;
    case 'd':
        control_sniffer_stop();
        control_sniffer_create_packets_log_file();
        break;
    case 'e':
        control_sniffer_stop();
        control_sniffer_reset();
        break;
    default:
        puts("Invalid option");
        break;
    }
}

void control_sniffer_actions()
{
    char action;

    buffer = (unsigned char *)malloc(PACKET_MAX_LEN);
    action = 0;
    while (action != 'b')
    {
        puts("\ns - start listening\nk - stop listening\ni - inspect packet\nd - create log file\ne - erase history\nb - exit the program");
        scanf(" %c", &action);
        control_sniffer_handle_action(action);
    }

    free(buffer);
}