#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <string.h>

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

void poke_string(pid_t pid, void *addr, const char *str, size_t len) {
    union {long val; char bytes[sizeof(long)]; } word;
    for(int i=0; i<len; i+=sizeof(long)) {
        memset(word.bytes, 0, sizeof(long));
        size_t bytes_count = (len - i < sizeof(long)) ? len - i : sizeof(long);
        memcpy(word.bytes, str + i, bytes_count);

        // even if the function signature says long ptrace(enum __ptrace_request op, pid_t pid, oid *addr, void *data);
        // for PTRACE_POKEDATA option, the final argument should be the data itself, and not a pointer to the data
        ptrace(PTRACE_POKEDATA, pid, addr + i, word.val);
    }
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

        // checking if signal is from a exec setup being completed
        if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
            printf("Child Finished setting up exec, returning control to child\n");
        }

        // checking is signal is from a syscall
        if(WSTOPSIG(status) == (SIGTRAP|0x80)) {
            if(!in_syscall) {
                in_syscall = 1;
                printf("caller_pid: %d\n", wait_pid);
                printf("entered syscall %s\n", get_syscall(regs.orig_rax));

                if (regs.orig_rax == 1) {
                    unsigned int fd = regs.rdi;
                    const char *buf = regs.rsi;
                    size_t count = regs.rdx;

                    char *str = "DISCO";
                    size_t len = strlen(str);
                    regs.rdx = len;
                    ptrace(PTRACE_SETREGS, wait_pid, NULL, &regs);
                    poke_string(wait_pid, (void *)buf, str, len);
                }

                fflush(stdout);
            } else {
                in_syscall = 0;
                printf("returned %lld\n\n", regs.rax);
            }
        }

        ptrace(PTRACE_SYSCALL, wait_pid, NULL, NULL);
    }
}