#pragma once

#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "print_packet.h"

extern pthread_t sniffer_thread;

/**
 * @brief receives an input from the user and executes the appropriate function
 * 
 */
void control_sniffer_actions();
