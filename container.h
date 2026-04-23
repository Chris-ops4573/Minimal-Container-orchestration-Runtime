#ifndef CONTAINER_H
#define CONTAINER_H

struct child_config {
    int argc;
    uid_t uid;
    int fd;
    char* hostname;
    char **argv;
    char* mount_dir;

    int io_fd;
};

int run_container(struct child_config *config);

#endif