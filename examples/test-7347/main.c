#include <stdio.h>
#include "xtimer.h"

int main(void)
{
    for (int i = 100; i > 0; i--){
        printf("going to sleep %d usecs...\n", i);
        xtimer_usleep(i);
    }
    return 0;
}
