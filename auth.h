#ifndef AUTH_H
#define AUTH_H

#include <stdio.h>

typedef enum {
    ROLE_USER,
    ROLE_ADMIN
} role_t;

typedef struct {
    char username[64];
    role_t role;
    int authenticated;
} session_t;

// API
int bootstrap_admin();
int signup(const char *username, const char *password, role_t role);
int login(const char *username, const char *password, session_t *session);

const char* role_to_string(role_t role);
role_t string_to_role(const char *str);

#endif