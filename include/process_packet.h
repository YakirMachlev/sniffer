#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#define PACKET_MAX_LEN 65536

extern FILE *temp_file;
extern int sock_raw;
extern int packet_id;
extern pthread_t sniffer_thread;
extern pthread_mutex_t mutex;

void print_packet_summary(unsigned char *buffer);
void print_packet_detailed(unsigned char *buffer, uint32_t len, FILE *file);
