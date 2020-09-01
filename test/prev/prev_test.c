#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/fcntl.h>

char EXEC_COUNT[] = "1000";
char *TARGETS[] = {
    "cp", "df", "echo", "false", "grep", "kill", "less", "ls", "mkdir",
    "mount", "mv", "rm", "rmdir", "tar", "touch", "true", "umount", "uname"
};

int main()
{
    struct timeval tv;
    long long interval;

    for (int i = 0; i < sizeof(TARGETS) / sizeof(char *); i++) {

        gettimeofday(&tv,NULL);
        interval = tv.tv_sec * 1000000 + tv.tv_usec;

        int pid = fork();
        if (pid == 0) {
            // int fd = open("/dev/null", O_WRONLY);
            // dup2(fd, STDOUT_FILENO);
            // dup2(fd, STDERR_FILENO);
            // close(fd);

            char *argv[] = { "./prev_test.sh", TARGETS[i], EXEC_COUNT, NULL };
            execvp("./prev_test.sh", argv);
        }
        waitpid(pid, NULL, 0);

        gettimeofday(&tv,NULL);
        interval = tv.tv_sec * 1000000 + tv.tv_usec - interval;

        printf("%s done in %lld μs.\n", TARGETS[i], interval);
    }

    return 0;
}