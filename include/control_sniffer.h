#pragma once

#include <pthread.h>
#include <stdbool.h>
#include "process_packet.h"

extern bool stop;

void *user_actions();