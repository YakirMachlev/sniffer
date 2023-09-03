#include "ui.h"

void handle_action(char action)
{
    switch (action)
    {
    case 's':
        stop = false;
        start_sniffing();
        break;
    case 'k':
        stop = true;
        break;
    case 'i':
        break;
    case 27: /* ESC */
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