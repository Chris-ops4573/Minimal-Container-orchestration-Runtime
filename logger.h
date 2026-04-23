#ifndef LOGGER_H
#define LOGGER_H

int log_event(const char *username,
              const char *event,
              const char *details);

int send_logs_to_client(int client_fd);

#endif