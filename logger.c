#define _GNU_SOURCE
#include "logger.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#define LOG_FILE "admin.log"
#define BUF_SIZE 4096

static int read_lock_file(int fd) {
    struct flock lock = {
        .l_type   = F_RDLCK,
        .l_whence = SEEK_SET,
        .l_start  = 0,
        .l_len    = 0
    };
    return fcntl(fd, F_SETLKW, &lock);
}

static int write_lock_file(int fd) {
    struct flock l = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };
    return fcntl(fd, F_SETLKW, &l);
}

static int unlock_file(int fd) {
    struct flock l = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };
    return fcntl(fd, F_SETLK, &l);
}

int log_event(const char *username, const char *event, const char *details){
    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;

    if (write_lock_file(fd) < 0) {
        close(fd);
        return -1;
    }

    // TIMESTAMP
    time_t t = time(NULL);
    char timebuf[64];
    int tlen = snprintf(timebuf, sizeof(timebuf), "%ld", t);

    char entry[1024];
    int len = snprintf(entry, sizeof(entry),
        "[time=%s][user=%s]\nEVENT: %s\nDETAILS: %s\n----\n",
        timebuf,
        username ? username : "unknown",
        event ? event : "none",
        details ? details : "none"
    );

    write(fd, entry, len);

    unlock_file(fd);
    close(fd);
    return 0;
}

int send_logs_to_client(int client_fd)
{
    int fd = open(LOG_FILE, O_RDONLY);
    if (fd < 0) {
        write(client_fd, "No logs available\n", 18);
        return -1;
    }

    if (read_lock_file(fd) < 0) {
        close(fd);
        return -1;
    }

    char buf[BUF_SIZE];
    int n;

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        write(client_fd, buf, n);
    }

    unlock_file(fd);
    close(fd);

    write(client_fd, "\n<<END>>\n", 9);
    return 0;
}