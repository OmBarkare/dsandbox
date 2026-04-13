#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

const char *syscalls[] = {
    [0] = "read",
    [1] = "write",
    [3] = "close",
    [5] = "fstat", // <-
    [9] = "mmap", // <-
    [10] = "mprotect", // <-
    [11] = "munmap", // <-
    [12] = "brk",
    [16] = "ioctl", // <-
    [17] = "pread64",
    [21] = "access",
    [137] = "statfs",
    [158] = "arch_prctl",
    [217] = "getdents64",
    [218] = "set_tid_address",
    [231] = "exit_group",
    [257] = "openat",
    [273] = "set_robust_list",
    [302] = "prlimit64",
    [318] = "getrandom",
    [334] = "rseq",
};

char *get_syscall(int syscall_id) {
    if(syscall_id < 0 || syscalls[syscall_id] == NULL) {
        return "unknown";
    }
    return syscalls[syscall_id];
}

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
    int in_syscall = 0;

    int wait_pid = wait(&status);
    
    ptrace(PTRACE_SETOPTIONS, wait_pid, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
    printf("set ptraceoptions\n\n");

    ptrace(PTRACE_SYSCALL, wait_pid, NULL, NULL);

    while(1) {
        wait_pid = wait(&status);

        if(WIFEXITED(status)) {
            printf("Child Exited with status code: %d\n\n", WEXITSTATUS(status));
            break;
        }

        struct user_regs_struct regs;
        
        ptrace(PTRACE_GETREGS, wait_pid, NULL, &regs);

        // checking if signal is from a exec call
        if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
            printf("CHILD CALLED EXEC\n");
        }

        // checking is signal is from a syscall
        if(WSTOPSIG(status) == (SIGTRAP|0x80)) {
            if(!in_syscall) {
                in_syscall = 1;
                printf("child_pid: %d\nwait_pid: %d\n", child_pid, wait_pid);
                printf("syscall_id: %lld\n", regs.orig_rax);
            } else {
                in_syscall = 0;
                printf("return val: %lld\n\n", regs.rax);
            }
        }

        ptrace(PTRACE_SYSCALL, wait_pid, NULL, NULL);
    }
}