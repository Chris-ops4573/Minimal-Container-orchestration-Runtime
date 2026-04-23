#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "auth.h"
#include "container.h"

#define PORT 8080

#define QUEUE_SIZE 64
#define THREAD_COUNT 4

// QUEUE LOGIC
typedef struct {
    int fds[QUEUE_SIZE];
    int front, rear, count;

    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} queue_t;

queue_t q;

void queue_init(queue_t *q) {
    q->front = q->rear = q->count = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

void enqueue(queue_t *q, int fd) {
    pthread_mutex_lock(&q->lock);

    while (q->count == QUEUE_SIZE)
        pthread_cond_wait(&q->not_full, &q->lock);

    q->fds[q->rear] = fd;
    q->rear = (q->rear + 1) % QUEUE_SIZE;
    q->count++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

int dequeue(queue_t *q) {
    pthread_mutex_lock(&q->lock);

    while (q->count == 0)
        pthread_cond_wait(&q->not_empty, &q->lock);

    int fd = q->fds[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;
    q->count--;

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);

    return fd;
}

// COMMAND PARSER
void build_config(char *input, struct child_config *config) {
    char* saveptr;
    char *token = strtok_r(input, " ", &saveptr);   

    token = strtok_r(NULL, " ", &saveptr);
    config->uid = atoi(token);

    token = strtok_r(NULL, " ", &saveptr);
    config->mount_dir = strdup(token);

    char *argv[200];
    int argc = 0;
    while ((token = strtok_r(NULL, " \n", &saveptr))) {
        argv[argc++] = strdup(token);
    }
    argv[argc] = NULL;

    config->argv = malloc(sizeof(char*) * (argc + 1));
    memcpy(config->argv, argv, sizeof(char*) * (argc + 1));
    config->argc = argc;
}

// WORKER
void *worker(void *arg) {
    int id = (int)(long)arg;

    while (1) {
        int client_fd = dequeue(&q);
        fprintf(stderr, "[thread %d] handling client\n", id);

        session_t session = {0};

        char buffer[1024];

        while (1) {
            memset(buffer, 0, sizeof(buffer));

            int total = 0;
            while (1) {
                int n = read(client_fd, buffer + total,
                             sizeof(buffer) - total - 1);
                if (n <= 0) break;
                total += n;
                if (buffer[total - 1] == '\n') break;
            }

            if (total <= 0) break;
            buffer[total] = '\0';

            // SIGNUP
            if (strncmp(buffer, "SIGNUP", 6) == 0) {
                char *saveptr;

                strtok_r(buffer, " ", &saveptr);
                char *user = strtok_r(NULL, " ", &saveptr);
                char *pass = strtok_r(NULL, " ", &saveptr);
                char *role = strtok_r(NULL, " \n", &saveptr);

                role_t r = string_to_role(role);

                if (signup(user, pass, r) == 0)
                    write(client_fd, "SIGNUP OK\n", 10);
                else
                    write(client_fd, "SIGNUP FAIL\n", 12);

                continue;
            }

            // LOGIN
            if (strncmp(buffer, "LOGIN", 5) == 0) {
                char *saveptr;

                strtok_r(buffer, " ", &saveptr);
                char *user = strtok_r(NULL, " ", &saveptr);
                char *pass = strtok_r(NULL, " \n", &saveptr);

                if (login(user, pass, &session) == 0)
                    write(client_fd, "LOGIN OK\n", 9);
                else
                    write(client_fd, "LOGIN FAIL\n", 11);

                continue;
            }

            if (!session.authenticated) {
                write(client_fd, "Please login first\n", 19);
                continue;
            }

            // CONTAINER LOGIC 
            if (strncmp(buffer, "RUN", 3) == 0) {
                struct child_config config = {0};
                build_config(buffer, &config);

                config.io_fd = client_fd;

                fprintf(stderr,
                        "[thread %d] user=%s running container\n",
                        id, session.username);

                run_container(&config);
                continue;
            }

            // END 
            if(strncmp(buffer, "END", 3) == 0) {
                write(client_fd, "<<END>>\n", 9);
                break;
            }

            write(client_fd, "Unknown command\n", 16);
        }

        close(client_fd);
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // ADD THIS before bind()
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "setsockopt SO_REUSEADDR");
        exit(1);
    }

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind");
        exit(1);
    }
    if (listen(server_fd, 5) < 0) {
        fprintf(stderr, "listen");
        exit(1);
    }

    fprintf(stderr, "Server listening on port %d...\n", PORT);

    queue_init(&q);

    pthread_t threads[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, worker, (void*)(long)i);
    }

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);

        if (client_fd < 0) {
            fprintf(stderr, "accept");
            continue;
        }

        enqueue(&q, client_fd);
    }
}