#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

void test_mount() {
    printf("\n[TEST] mount escape\n");
    if (mount("none", "/tmp", "tmpfs", 0, NULL) == -1) {
        printf("✔ mount blocked: %s\n", strerror(errno));
    } else {
        printf("✘ mount succeeded (BAD)\n");
    }
}

void test_ptrace() {
    printf("\n[TEST] ptrace\n");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        printf("✔ ptrace blocked: %s\n", strerror(errno));
    } else {
        printf("✘ ptrace allowed (BAD)\n");
    }
}

void test_userns() {
    printf("\n[TEST] unshare user namespace\n");
    if (unshare(CLONE_NEWUSER) == -1) {
        printf("✔ unshare blocked: %s\n", strerror(errno));
    } else {
        printf("✘ unshare succeeded (BAD)\n");
    }
}

void test_proc_escape() {
    printf("\n[TEST] /proc escape\n");
    int fd = open("/proc/1/root/etc/passwd", O_RDONLY);
    if (fd == -1) {
        printf("✔ cannot access host root: %s\n", strerror(errno));
    } else {
        printf("✘ accessed host root (BAD)\n");
        close(fd);
    }
}

void test_privilege_effectiveness() {
    printf("\n[TEST] container root effectiveness\n");

    if (setuid(0) == -1) {
        printf("setuid failed (expected in some configs): %s\n", strerror(errno));
        return;
    }

    printf("Now running as UID 0 inside container\n");

    // Try something that requires real privilege
    if (mount("none", "/tmp", "tmpfs", 0, NULL) == -1) {
        printf("✔ even as root, mount blocked: %s\n", strerror(errno));
    } else {
        printf("✘ root has real power (BAD)\n");
    }
}

void test_raw_socket() {
    printf("\n[TEST] raw socket\n");
    int s = socket(AF_INET, SOCK_RAW, 0);
    if (s == -1) {
        printf("✔ raw socket blocked: %s\n", strerror(errno));
    } else {
        printf("✘ raw socket allowed (BAD)\n");
        close(s);
    }
}

void test_forkbomb() {
    printf("\n[TEST] fork bomb (pids limit)\n");
    int count = 0;

    while (1) {
        pid_t pid = fork();
        if (pid < 0) {
            printf("✔ fork limited at %d processes: %s\n", count, strerror(errno));
            break;
        } else if (pid == 0) {
            pause();
            exit(0);
        }
        count++;
    }
}

void test_fd_limit() {
    printf("\n[TEST] file descriptor exhaustion\n");
    int fds[1024];
    int count = 0;

    for (int i = 0; i < 1024; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            printf("✔ fd limit hit at %d: %s\n", count, strerror(errno));
            break;
        }
        fds[count++] = fd;
    }

    for (int i = 0; i < count; i++) close(fds[i]);
}

int main() {
    printf("=== Container Breakout Test ===\n");

    test_mount();
    test_ptrace();
    test_userns();
    test_proc_escape();
    test_privilege_effectiveness();
    test_raw_socket();
    test_forkbomb();
    test_fd_limit();

    printf("\n=== Test Complete ===\n");
    return 0;
}