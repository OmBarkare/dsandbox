#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_binary> [args...] \n", argv[0]);
        return 1;
    }

    int child_pid = fork();

    if(child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // (enum, pid, addr, payload/signal)

        execvp(argv[1], &argv[1]); // &argv[1] is passed instead of &argv[2] because this entire array will be copied into the memory space of the new process as its argument array, and a process expects its first argument to be the name of the program itself

        fprintf(stderr, "execvp failed");
        return 1;
    }

    int status = 0;
    while(1) {
        int wait_pid = wait(&status);

        printf("child_pid: %d\nwait_pid: %d\n", child_pid, wait_pid);

        if(WIFEXITED(status)) {
            printf("Child Exited with status code: %d\n\n", WEXITSTATUS(status));
            break;
        }

        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, wait_pid, NULL, &regs);

        printf("syscall_id: %lld\n\n", regs.orig_rax);

        ptrace(PTRACE_SYSCALL, wait_pid, NULL, NULL);
    }
}