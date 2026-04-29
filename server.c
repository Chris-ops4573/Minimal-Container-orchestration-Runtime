#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>

#include "auth.h"
#include "container.h"
#include "logger.h"

#define PORT 8080

#define QUEUE_SIZE 64
#define THREAD_COUNT 4

typedef struct {
    int fd;
    char buffer[1024];
} job_t;

// QUEUE LOGIC
typedef struct {
    job_t jobs[QUEUE_SIZE];
    int front, rear;

    pthread_mutex_t lock;
    sem_t items;
    sem_t spaces;
} queue_t;

queue_t q;

void queue_init(queue_t *q) {
    q->front = q->rear = 0;
    pthread_mutex_init(&q->lock, NULL);
    sem_init(&q->items, 0, 0);
    sem_init(&q->spaces, 0, QUEUE_SIZE);
}

void enqueue(queue_t *q, job_t job) {
    sem_wait(&q->spaces);

    pthread_mutex_lock(&q->lock);

    q->jobs[q->rear] = job;
    q->rear = (q->rear + 1) % QUEUE_SIZE;

    pthread_mutex_unlock(&q->lock);
    sem_post(&q->items);
}

job_t dequeue(queue_t *q) {
    sem_wait(&q->items);

    pthread_mutex_lock(&q->lock);

    job_t job = q->jobs[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;

    pthread_mutex_unlock(&q->lock);
    sem_post(&q->spaces);

    return job;
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

int make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// WORKER
void *worker(void *arg) {
    int id = (int)(long)arg;

    while (1) {
        job_t job = dequeue(&q);
        int client_fd = job.fd;
        char* buffer = job.buffer;

        fprintf(stderr, "[thread %d] handling client\n", id);

        session_t *session = session_get(client_fd);
        if(!session){
            write(client_fd, "Session failed!\n", 16);
            close(client_fd);
            session_delete(client_fd);
            continue;
        }
            
        // END 
        if(strncmp(buffer, "END", 3) == 0) {
            write(client_fd, "<<END>>\n", 9);
            
            close(client_fd);
            session_delete(client_fd);
            continue;
        }

        // SIGNUP
        if (strncmp(buffer, "SIGNUP", 6) == 0) {
            char *saveptr;

            strtok_r(buffer, " ", &saveptr);
            char *user = strtok_r(NULL, " ", &saveptr);
            char *pass = strtok_r(NULL, " ", &saveptr);
            char *role = strtok_r(NULL, " \n", &saveptr);

            if(!role || !pass || !user){
                write(client_fd, "USAGE: SIGNUP <username> <password> USER\n", 41);
                continue;
            }

            if(strcmp(role, "USER") != 0){
                write(client_fd, "SIGNUP FAILED: role must be USER\n", 33);
                continue;
            }

            role_t r = string_to_role(role);

            if (signup(user, pass, r) == 0){
                write(client_fd, "SIGNUP OK\n", 10);
                log_event(user, "SIGNUP", "user created");
            }
            else{
                write(client_fd, "SIGNUP FAIL\n", 12);
            }

            continue;
        }

        // LOGIN
        if (strncmp(buffer, "LOGIN", 5) == 0) {
            char *saveptr;

            strtok_r(buffer, " ", &saveptr);
            char *user = strtok_r(NULL, " ", &saveptr);
            char *pass = strtok_r(NULL, " \n", &saveptr);

            if (login(user, pass, session) == 0){
                write(client_fd, "LOGIN OK\n", 9);
                log_event(user, "LOGIN", "user logged in");
            }
            else{
                write(client_fd, "LOGIN FAIL\n", 11);
                log_event(user, "LOGIN", "failed");
            }

            continue;
        }

        if (!session->authenticated) {
            write(client_fd, "Please login first\n", 19);
            continue;
        }

        // CONTAINER LOGIC 
        if (strncmp(buffer, "RUN", 3) == 0) {
            log_event(session->username, "RUN", buffer);
            
            struct child_config config = {0};
            build_config(buffer, &config);

            config.io_fd = client_fd;

            fprintf(stderr,
                    "[thread %d] user=%s running container\n",
                    id, session->username);

            int ret = run_container(&config);

            // CONTAINER RETURN STATUS LOGGED
            if(ret == 1)
                log_event(session->username, "RUN", "failed");
            else
                log_event(session->username, "RUN", "succeeded");

            continue;
        }

        // ADMIN LOG REQUEST
        if (strncmp(buffer, "GET_LOGS", 8) == 0) {
            if (session->role != ROLE_ADMIN) {
                log_event(session->username, "GET_LOGS", "failed");

                write(client_fd, "Permission denied\n", 18);
                continue;
            }

            log_event(session->username, "GET_LOGS", "succeeded");
            send_logs_to_client(client_fd);
            continue;
        }

        write(client_fd, "Unknown command\nUsage: RUN <process_uid> <path_to_code_files> <executable_command>\n", 80);
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    bootstrap_admin();

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

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

    int epfd = epoll_create1(0);

    struct epoll_event ev, events[64];

    make_nonblocking(server_fd);

    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &ev);

    while (1) {
        int n = epoll_wait(epfd, events, 64, -1);

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == server_fd) {
                while (1) {
                    int client_fd = accept(server_fd, NULL, NULL);
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        else
                            break;
                    }

                    make_nonblocking(client_fd);
                    session_create(client_fd);

                    struct epoll_event cev;
                    cev.events = EPOLLIN;
                    cev.data.fd = client_fd;

                    epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &cev);
                }
            }

            else {
                char buffer[1024];
                int nread = read(fd, buffer, sizeof(buffer) - 1);

                if (nread <= 0) {
                    close(fd);
                    session_delete(fd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
                    continue;
                }

                buffer[nread] = '\0';

                job_t job = { .fd = fd };
                strcpy(job.buffer, buffer);

                enqueue(&q, job);
            }
        }
    }
}