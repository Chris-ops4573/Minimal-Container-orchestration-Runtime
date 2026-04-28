# Secure Containerized Execution Server

## Problem Statement

This project implements a multi-user client-server system that allows authenticated users to execute commands inside secure, isolated containers. The system demonstrates core Operating Systems concepts such as concurrency, synchronization, IPC, file locking, and role-based access control.

---

## System Overview

The system follows a client-server architecture:

- Client sends commands over a TCP socket  
- Server handles multiple clients concurrently  
- Authentication and authorization enforce access control  
- Commands execute inside isolated containers  
- All actions are logged  

Flow:

Client → Server → Authentication → Authorization → Container Execution → Response

---

## File Structure

- `server.c`  
  Main server implementation using epoll and thread pool

- `client.c`  
  TCP client interface

- `auth.c`, `auth.h`  
  Authentication, session handling, role management

- `container.c`, `container.h`  
  Container runtime using Linux namespaces, cgroups, seccomp

- `logger.c`, `logger.h`  
  Logging system with safe concurrent access

- `breakout.c`  
  Security test suite for container isolation

---

## Build Instructions

Compile using:

```bash
gcc server.c auth.c container.c logger.c -o server -lpthread -lseccomp -lcap -lcrypt
gcc client.c -o client
```

Run server (requires root for namespaces and cgroups):

```bash
sudo ./server
```

Run client:

```bash
./client
```

---

## Supported Commands

- `SIGNUP <username> <password> USER`
- `LOGIN <username> <password>`
- `RUN <uid> <rootfs> <command>`
- `GET_LOGS` (admin only)
- `END`

---

## Implementation of Mandatory OS Concepts

### 1. Role-Based Authorization

- Roles defined as `ROLE_USER` and `ROLE_ADMIN`
- Stored in `session_t`
- Enforced in server before privileged operations

Example:
- Only ADMIN can execute `GET_LOGS`
- USER can execute container commands

Bootstrap admin is automatically created if none exists.

---

### 2. File Locking

File locking is implemented using `fcntl()`.

- User database (`users.db`) is write-locked during signup/login
- Log file (`admin.log`) uses:
  - Read locks for reading logs
  - Write locks for writing logs

This prevents concurrent corruption of shared files.

---

### 3. Concurrency Control

The server handles concurrency using:

- Thread pool (`pthread_create`)
- Mutex locks (`pthread_mutex_t`)
- Condition variables (`pthread_cond_t`)

Producer-Consumer queue:
- Main thread enqueues client requests
- Worker threads dequeue and process

Ensures:
- No race conditions
- Efficient parallel handling of clients

---

### 4. Data Consistency

Maintained using:

- Mutex protection on shared structures (job queue, sessions)
- File locking for persistent data
- Atomic operations inside critical sections

Prevents:
- Race conditions
- Lost updates
- Dirty reads

---

### 5. Socket Programming

Client-server communication uses TCP sockets:

- `socket()`, `bind()`, `listen()`, `accept()` in server
- `connect()` in client
- `read()` / `write()` for communication

The server uses `epoll` for efficient I/O multiplexing and handling multiple clients.

---

### 6. Inter-Process Communication (IPC)

Multiple IPC mechanisms are used:

1. Socket communication  
   - Between client and server  

2. `socketpair()`  
   - Between parent and container process for UID mapping  

3. File descriptor redirection (`dup2`)  
   - Connects container I/O to client  

4. Process creation (`clone`)  
   - Used to spawn container processes  

---

## Containerization Features

Implemented using Linux primitives:

### Namespaces
- Mount namespace (`CLONE_NEWNS`)
- PID namespace (`CLONE_NEWPID`)
- Network namespace (`CLONE_NEWNET`)
- UTS namespace (`CLONE_NEWUTS`)
- IPC namespace (`CLONE_NEWIPC`)
- Cgroup namespace (`CLONE_NEWCGROUP`)

### Filesystem Isolation
- `pivot_root()` used to isolate filesystem

### Cgroups (v2)
- Memory limit
- CPU weight
- PID limit
- I/O weight

### Seccomp Filtering
Blocks dangerous syscalls such as:
- `ptrace`
- `keyctl`
- `unshare`
- privilege escalation attempts

### Capabilities Dropping
Removes dangerous kernel capabilities using `prctl` and libcap.

### Resource Limits
- File descriptor limit via `setrlimit`

---

## Security Testing

The `breakout.c` program tests isolation:

- Mount escape attempts
- ptrace usage
- user namespace creation
- raw socket access
- fork bomb (PID limit)
- file descriptor exhaustion

All tests are expected to fail inside the container, proving isolation.

---

## Key Highlights

- Fully concurrent server using thread pool + epoll  
- Secure authentication with hashed passwords  
- Strong isolation using namespaces + cgroups + seccomp  
- Safe file handling using locks  
- Multiple IPC mechanisms demonstrated  
- Clear separation of modules  

---