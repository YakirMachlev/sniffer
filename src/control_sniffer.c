#include "control_sniffer.h"

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
            printf("Recvfrom error, failed to get packets\n");
            exit(1);
        }
        print_packet_summary(buffer, buffer_len);
    }
}

void inspect_packet()
{
    uint32_t id;
    /* something with lock */

    id = 1;
    while (id)
    {
        printf("Enter the packet id: ");
        scanf("%d", id);

        fseek(temp_file, id * PACKET_MAX_LEN, SEEK_SET);
        fread(buffer, 1, PACKET_MAX_LEN, temp_file);

        print_packet_detailed(buffer, strlen(buffer), stdin);        
    }
}

void create_packets_log_file()
{
    char file_name[256];
    FILE *log_file;

    /* get date and hour */
    sprintf(file_name, "my_sniffer_%s_%s", date, hour);
    log_file = fopen(file_name, "w");

    rewind(temp_file);
    while (!feof(temp_file))
    {
        fread(buffer, 1, PACKET_MAX_LEN, temp_file);  
        print_packet_detailed(buffer, strlen(buffer), log_file); 
        temp_file += PACKET_MAX_LEN;
    }
}

void reset_sniffer()
{
    packet_id = 0;
    /* check how to clear the screen */
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
        handle_action(action);
    }

    pthread_exit(NULL);
}