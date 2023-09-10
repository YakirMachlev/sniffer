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
#include <sys/socket.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define PACKET_MAX_LEN 65536
#define PACKET_LEN_SIZE sizeof(int)

extern FILE *temp_file;
extern int sock_raw;
extern int packet_id;

/**
 * @brief prints a summary of the received packet, containing the packet
 * protocol, plus the source and dest addresses and ports
 * 
 * @param buffer the packet
 * @param len the packet length
 */
void print_packet_summary(unsigned char *buffer, uint32_t len);

/**
 * @brief prints a detailed description of the received packet, containing
 * the ethernet and ip headers, the network layer header (tcp/udp/icmp) with
 * all of its information, and the contained data
 * 
 * @param buffer the packet
 * @param len the packet length
 * @param file the file to which the detailed information will be written to
 */
void print_packet_detailed(unsigned char *buffer, uint32_t len, FILE *file);
