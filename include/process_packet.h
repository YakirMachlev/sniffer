#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define PACKET_MAX_LEN 65536

extern FILE *temp_file;
extern int sock_raw;
extern unsigned char *buffer;
extern int packet_id;

void print_packet_summary(unsigned char *buffer, int len);
void print_packet_detailed(unsigned char *buffer, int len, FILE *file);
