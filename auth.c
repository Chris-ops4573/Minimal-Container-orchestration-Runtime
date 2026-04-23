#define _GNU_SOURCE
#include "auth.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <crypt.h>
#include <stdio.h>

#define USER_DB "users.db"
#define BUF_SIZE 4096

const char* role_to_string(role_t role) {
    switch(role) {
        case ROLE_ADMIN: return "ADMIN";
        case ROLE_USER: return "USER";
        default: return "USER";
    }
}

role_t string_to_role(const char *str) {
    if (!str) return ROLE_USER;
    if (strcmp(str, "ADMIN") == 0) return ROLE_ADMIN;
    if (strcmp(str, "USER") == 0) return ROLE_USER;
    return ROLE_USER;
}

// LOCKING
static int lock_file(int fd) {
    struct flock lock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };
    return fcntl(fd, F_SETLKW, &lock);
}

static int unlock_file(int fd) {
    struct flock lock = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };
    return fcntl(fd, F_SETLK, &lock);
}

static int read_all(int fd, char *buf, size_t size) {
    lseek(fd, 0, SEEK_SET);

    ssize_t total = 0;
    while (total < (ssize_t)(size - 1)) {
        ssize_t n = read(fd, buf + total, size - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    return total;
}

static int user_exists(int fd, const char *username) {
    char buf[BUF_SIZE];
    read_all(fd, buf, sizeof(buf));

    char *save_line;
    char *line = strtok_r(buf, "\n", &save_line);

    while (line) {
        char *save_field;
        char *file_user = strtok_r(line, ":", &save_field);

        if (file_user && strcmp(file_user, username) == 0)
            return 1;

        line = strtok_r(NULL, "\n", &save_line);
    }
    return 0;
}

int admin_exists() {
    int fd = open(USER_DB, O_RDONLY);
    if (fd < 0) return 0;

    char buf[BUF_SIZE];
    read_all(fd, buf, sizeof(buf));

    char *save_line;
    char *line = strtok_r(buf, "\n", &save_line);

    while (line) {
        char *save_field;
        strtok_r(line, ":", &save_field);           // username
        strtok_r(NULL, ":", &save_field);           // hash
        char *role = strtok_r(NULL, ":\n", &save_field);

        if (role && strcmp(role, "ADMIN") == 0) {
            close(fd);
            return 1;
        }

        line = strtok_r(NULL, "\n", &save_line);
    }

    close(fd);
    return 0;
}

int bootstrap_admin() {
    if (admin_exists()) return 0;

    fprintf(stderr, "[BOOTSTRAP] No admin found. Creating default admin...\n");

    if (signup("admin", "admin123", ROLE_ADMIN) == 0) {
        fprintf(stderr, "[BOOTSTRAP] Admin created: admin/admin123\n");
        return 0;
    }

    fprintf(stderr, "[BOOTSTRAP] Failed to create admin\n");
    return -1;
}

int signup(const char *username, const char *password, role_t role) {
    if (!username || !password) return -1;

    int fd = open(USER_DB, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;

    if (lock_file(fd) < 0) {
        close(fd);
        return -1;
    }

    if (user_exists(fd, username)) {
        unlock_file(fd);
        close(fd);
        return -1;
    }

    // SALT CREATION
    char salt[64];
    snprintf(salt, sizeof(salt), "$6$%ld$", random());

    struct crypt_data data;
    data.initialized = 0;
    char *hash = crypt_r(password, salt, &data);

    if (!hash) {
        unlock_file(fd);
        close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_END);

    char entry[512];
    int len = snprintf(entry, sizeof(entry), "%s:%s:%s\n",
                       username, hash, role_to_string(role));

    write(fd, entry, len);

    unlock_file(fd);
    close(fd);
    return 0;
}

int login(const char *username, const char *password, session_t *session) {
    if (!username || !password || !session) return -1;

    int fd = open(USER_DB, O_RDWR);
    if (fd < 0) return -1;

    if (lock_file(fd) < 0) {
        close(fd);
        return -1;
    }

    char buf[BUF_SIZE];
    read_all(fd, buf, sizeof(buf));

    char *save_line;
    char *line = strtok_r(buf, "\n", &save_line);

    while (line) {
        char *save_field;

        char *file_user = strtok_r(line, ":", &save_field);
        char *file_hash = strtok_r(NULL, ":", &save_field);
        char *file_role = strtok_r(NULL, ":\n", &save_field);

        if (!file_user || !file_hash || !file_role) {
            line = strtok_r(NULL, "\n", &save_line);
            continue;
        }

        if (strcmp(file_user, username) == 0) {
            struct crypt_data data;
            data.initialized = 0;

            char *computed = crypt_r(password, file_hash, &data);

            if (computed && strcmp(computed, file_hash) == 0) {
                session->authenticated = 1;

                strncpy(session->username, username,
                        sizeof(session->username) - 1);
                session->username[sizeof(session->username)-1] = '\0';

                session->role = string_to_role(file_role);

                unlock_file(fd);
                close(fd);
                return 0;
            } else {
                unlock_file(fd);
                close(fd);
                return -1;
            }
        }

        line = strtok_r(NULL, "\n", &save_line);
    }

    unlock_file(fd);
    close(fd);
    return -1;
}