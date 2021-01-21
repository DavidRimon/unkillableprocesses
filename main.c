#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

void my_handler(int signum) {
    printf("I get %d signum, and i'm not going anywhere!!\n" , signum);
}

void setup_signal(int signum) {
    struct sigaction act = {0};
    // memset(&act, 0, sizeof(act));
    act.sa_handler = my_handler;
    if (0 != sigaction(signum, &act, NULL)) {
        printf("I have failed setting handler for signum: %d. DAMN THE BASTERDS!!!\n", signum);
    }
}
void main() {
    for (size_t i = 0; i < 64; i++)
    {
        setup_signal(i);
    }
    printf("hello world, my pid is: %d\n", getpid());
    while(1) sleep(100);
}
