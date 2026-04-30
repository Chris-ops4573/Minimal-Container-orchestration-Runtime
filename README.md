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

- `test_dir/breakout.c`  
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
- `STOP_SERVER` (admin only)
- `END`

---

## Implementation of Mandatory OS Concepts

### 1. Role-Based Authorization

- Roles defined as `ROLE_USER` and `ROLE_ADMIN`
- Stored in `session_t`
- Enforced in server before privileged operations

Example:
- Only ADMIN can execute `GET_LOGS` and `STOP_SERVER`
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

The server uses a hybrid model combining **epoll-based event-driven I/O** with a **thread pool**.

- The main thread uses `epoll` to monitor all client sockets (non-blocking)
- Incoming requests are converted into **jobs** and pushed into a queue
- Worker threads dequeue and process jobs

Key design decision:
- Threads handle **jobs**, not individual client connections
- This ensures threads are never blocked waiting on I/O
- All socket I/O is handled asynchronously via `epoll`

This results in:
- Fully non-blocking worker threads  
- Better scalability under multiple clients  
- Clear separation between I/O handling and computation  

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

### Execution Model

This system executes programs using `execve`, meaning all workloads ultimately run as binaries within the container.

- Compiled binaries run directly  
- Interpreted programs (e.g., Python) require the corresponding interpreter to exist inside the container filesystem  
- The system does not provide dependency management or runtime provisioning  

As a result, this runtime focuses on **secure process execution and isolation**, rather than full environment replication like Docker.

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

## How to test?

- Make sure server and client are running.
- Run - LOGIN admin admin123 (or create new user by signing up)
- Run - RUN 0 test_dir ./breakout (make sure you compile breakout.c with the -static flag)
- See the test results

- Note: This project does not support dependency management or environment replication inside the container.  
  All programs must either:
  - be statically compiled binaries, or  
  - rely on interpreters/libraries already present in the container filesystem.  

---

## Server Shutdown Behavior

The `STOP_SERVER` command implements a **lazy shutdown mechanism**.

- The server process is terminated immediately using a signal-based kill  
- No coordinated cleanup is performed  

As a result, the following are **not guaranteed to be cleaned up gracefully**:

- cgroups created for container resource control  
- mount namespaces and bind mounts  
- running container processes beyond OS-level termination  
- in-flight jobs or active client sessions  

The operating system reclaims most resources (memory, file descriptors, processes), but some artifacts (such as cgroup directories or mounts) may persist temporarily. So it is recommended to let a container finish execution before killing the server (the `run_container` function performs cleanup when allowed to complete).

This design choice was made to keep the implementation simple and within project scope.

---

## Key Highlights

- Fully concurrent server using thread pool + epoll  
- Non-blocking design with epoll-driven I/O and job-based worker threads  
- Secure authentication with hashed passwords  
- Strong isolation using namespaces + cgroups + seccomp  
- Safe file handling using locks  
- Multiple IPC mechanisms demonstrated  
- Clear separation of modules  