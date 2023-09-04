#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include "process_packet.h"

void *user_actions();
void start_sniffing();