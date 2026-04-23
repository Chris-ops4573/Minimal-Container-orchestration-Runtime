#define _GNU_SOURCE
#include<errno.h>
#include<fcntl.h>
#include<pwd.h>
#include<grp.h>
#include<sched.h>
#include<seccomp.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<unistd.h>
#include<sys/capability.h>
#include<sys/mount.h>
#include<sys/prctl.h>
#include<sys/resource.h>
#include<sys/socket.h>
#include<sys/stat.h>
#include<sys/syscall.h>
#include<sys/utsname.h>
#include<sys/wait.h>
#include<linux/capability.h>
#include<linux/limits.h>

#include "container.h"

#define STACK_SIZE (1024*1024)

#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

#define MEMORY "1073741824"
#define SHARES "256"
#define PIDS "64"
#define WEIGHT "10"
#define FD_COUNT 64

int run_container(struct child_config *config);

//FS NAMESPACING
int mounts(struct child_config *config);
int pivot_root(const char *new_root, const char *put_old);

//REMOVING CAPABILITIES AND SYSCALLS
int syscalls();
int capabilities();

//CGROUPS
int resources(struct child_config *config);
int assign_to_cgroups(pid_t child_pid, struct child_config *config);
int free_resources(struct child_config *config);

//CHILD FUNCTION
int child(void *arg);

//NAMESPACING AND HOSTNAME
int userns(struct child_config *config);
int handle_child_uid_map(pid_t child_pid, int fd);
int choose_hostname(char* buff, size_t len);

/*
int main(int argc, char* argv[]){
		struct child_config config = {0};
		int option = 0;
		int last_optind = 0;

		while((option = getopt(argc, argv, "c:m:u:")) != -1){
                switch(option){
                        case 'c':
                                config.argc = argc - last_optind - 1;
                                config.argv = &argv[argc - config.argc];
                                goto finish_options;
                        case 'm':
                                config.mount_dir = optarg;
                                break;
                        case 'u':
                                if(sscanf(optarg, "%d", &config.uid) != 1){
                                        fprintf(stderr, "badly formatted uid: %s\n", optarg);
                                        goto usage;
                                }
                                break;
                        default:
                                goto usage;
                }
                
                last_optind = optind;
        }

		finish_options:
				if (!config.argc || !config.mount_dir)
						goto usage;

				return run_container(&config);

		usage:
				fprintf(stderr, "Usage: %s -u <uid> -m <mount_dir> -c <cmd>\n", argv[0]);
				return 1;
}
*/

int run_container(struct child_config *config){
        int err = 0;
        int sockets[2] = {0};
        pid_t child_pid = 0;

		//CHECKING LINUX VERSION
		fprintf(stderr, "=> Validating Linux version...\n");
		struct utsname host = {0};
		if(uname(&host)){
				fprintf(stderr, "failed %m\n");
				err = 1;
				goto cleanup;
		}
		int major = -1;
		int minor = -1;
		if(sscanf(host.release, "%u.%u.", &major, &minor) != 2){
				goto cleanup;
		}
		if(major < 4){
				fprintf(stderr, "expected 4 or greater %s\n", host.release);
				goto cleanup;
		}
		if(strcmp("x86_64", host.machine)){
				fprintf(stderr, "expected x84_64 machine: %s\n", host.machine);
				goto cleanup;
		}
		fprintf(stderr, "%s on %s.\n", host.release, host.machine);

		//SETTING HOSTNAME
		char hostname[256] = {0};
		if(choose_hostname(hostname, sizeof(hostname))) goto error;
		config->hostname = hostname;

		//SETTING UP NAMESPACES
		if(socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)){
				fprintf(stderr, "socket pair failed \n");
				goto error;
		}
		if(fcntl(sockets[0], F_SETFD, FD_CLOEXEC)){
				fprintf(stderr, "child process socket config failed \n");
				goto error;
		}
		config->fd = sockets[1];

		char *stack = 0;
		if(!(stack = malloc(STACK_SIZE))){
				fprintf(stderr, "=> malloc failed, out of memory? \n");
				goto error;
		}
				
		//PREPARING RESOURCE LIMITING(CGROUPS)
		int resource_exists = 0;
		if(resources(config)){
				err = 1;
				goto clear_resources;
		}
		resource_exists = 1;

		//SETTING UP AND CLONING
		int flags = CLONE_NEWNS
				| CLONE_NEWCGROUP
				| CLONE_NEWPID 
				| CLONE_NEWIPC
				| CLONE_NEWNET
				| CLONE_NEWUTS;
		if ((child_pid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, config)) == -1){
				fprintf(stderr, "=> clone failed! %m\n");
				err = 1;
				goto clear_resources;
		}

		if(assign_to_cgroups(child_pid, config)) {
				err = 1; 
				goto clear_resources;
		}
		
		if(handle_child_uid_map(child_pid, sockets[0])) {
				err = 1;
				goto clear_resources;
		}


		if(waitpid(child_pid, NULL, 0) == -1){
				fprintf(stderr, "=> Child didn't exit or failed\n");
				err = 1;
		}

		close(sockets[1]);
		sockets[1] = 0;
		
		
		goto clear_resources;

        error:
                err = 1;

        clear_resources:
                if(resource_exists) free_resources(config);

        cleanup:
                if(stack) free(stack);

                if(sockets[0]) close(sockets[0]);
                if(sockets[1]) close(sockets[1]);

                return err;
}


int capabilities(){
        fprintf(stderr, "=> dropping capabilities...\n");

        int drop_caps[] = {
		CAP_AUDIT_CONTROL,
		CAP_AUDIT_READ,
		CAP_AUDIT_WRITE,
                CAP_BLOCK_SUSPEND,
		CAP_DAC_READ_SEARCH,
		CAP_FSETID,
		CAP_IPC_LOCK,
		CAP_MAC_ADMIN,
		CAP_MAC_OVERRIDE,
		CAP_MKNOD,
                CAP_SETFCAP,
		CAP_SYSLOG,
		CAP_SYS_ADMIN,
		CAP_SYS_BOOT,
                CAP_SYS_MODULE,
		CAP_SYS_NICE,
		CAP_SYS_RAWIO,
		CAP_SYS_RESOURCE,
		CAP_SYS_TIME,
		CAP_WAKE_ALARM
        };

        size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
	fprintf(stderr, "bounding...\n");
	for (size_t i = 0; i < num_caps; i++){
		if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
			fprintf(stderr, "prctl failed: %m\n");
			return 1;
		}
	}
	fprintf(stderr, "inheritable...\n");
	cap_t caps = NULL;
	if (!(caps = cap_get_proc())
	    || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
	    || cap_set_proc(caps)) {
		fprintf(stderr, "failed: %m\n");
		if (caps) cap_free(caps);
		return 1;
	}
	cap_free(caps);
	fprintf(stderr, "done.\n");
	return 0;
}

int pivot_root(const char *new_root, const char *put_old){
	return syscall(SYS_pivot_root, new_root, put_old);
}

int mounts(struct child_config *config){
	fprintf(stderr, "=> remounting everything with MS_PRIVATE...\n");
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		fprintf(stderr, "failed! %m\n");
		return -1;
	}
	fprintf(stderr, "remounted.\n");

	fprintf(stderr, "=> making a temp directory and a bind mount there...\n");
	char mount_dir[] = "/tmp/tmp.XXXXXX";
	if (!mkdtemp(mount_dir)) {
		fprintf(stderr, "failed making a directory!\n");
		return -1;
	}

	if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
		fprintf(stderr, "bind mount failed!\n");
		return -1;
	}

	char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
	memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
	if (!mkdtemp(inner_mount_dir)) {
		fprintf(stderr, "failed making the inner directory!\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

	fprintf(stderr, "=> pivoting root...\n");
	if (pivot_root(mount_dir, inner_mount_dir)) {
		fprintf(stderr, "failed!\n");
		return -1;
	}
	fprintf(stderr, "done.\n");

	char *old_root_dir = basename(inner_mount_dir);
	char old_root[sizeof(inner_mount_dir) + 1] = { "/" };
	strcpy(&old_root[1], old_root_dir);

	fprintf(stderr, "=> unmounting %s...\n", old_root);
	if (chdir("/")) {
		fprintf(stderr, "chdir failed! %m\n");
		return -1;
	}
	if (umount2(old_root, MNT_DETACH)) {
		fprintf(stderr, "umount failed! %m\n");
		return -1;
	}
	if (rmdir(old_root)) {
		fprintf(stderr, "rmdir failed! %m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}

int syscalls(){
        scmp_filter_ctx ctx = NULL;
        fprintf(stderr, "=> filtering syscalls...\n");
        if (!(ctx = seccomp_init(SCMP_ACT_ALLOW))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
				SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
				SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
				SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
				SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
				SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
				SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1,
				SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
				SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI))
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0)
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0)
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0)
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0)
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0)
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0)
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0)
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0)
	    || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0)
	    || seccomp_load(ctx)) {
		if (ctx) seccomp_release(ctx);
		fprintf(stderr, "failed: %m\n");
		return 1;
	}
	seccomp_release(ctx);
	fprintf(stderr, "done.\n");
	return 0;
}

int resources(struct child_config *config){
    char dir[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    int fd = 0;

    fprintf(stderr, "=> setting cgroups v2...");

    // CREATE
    if(snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s", config->hostname) < 0){
        fprintf(stderr, "snprintf failed: %m\n");
        return -1;
    }
    if(mkdir(dir, 0755)){
        fprintf(stderr, "mkdir %s failed: %m\n", dir);
        return -1;
    }

    // INITIALIZE CGROUP
    if((fd = open("/sys/fs/cgroup/cgroup.subtree_control", O_WRONLY)) == -1){
        fprintf(stderr, "opening subtree_control failed: %m\n");
        return -1;
    }
    if(write(fd, "+memory +pids +cpu +io", 22) == -1){
        fprintf(stderr, "writing subtree_control failed: %m\n");
        close(fd);
        return -1;
    }
    close(fd);

    // MEMORY
    if(snprintf(path, sizeof(path), "%s/memory.max", dir) < 0){
        fprintf(stderr, "snprintf failed: %m\n");
        return -1;
    }
    if((fd = open(path, O_WRONLY)) == -1){
        fprintf(stderr, "opening memory.max failed: %m\n");
        return -1;
    }
    if(write(fd, MEMORY, strlen(MEMORY)) == -1){
        fprintf(stderr, "writing memory.max failed: %m\n");
        close(fd);
        return -1;
    }
    close(fd);

    // CPU LIMIT
    if(snprintf(path, sizeof(path), "%s/cpu.weight", dir) < 0){
        fprintf(stderr, "snprintf failed: %m\n");
        return -1;
    }
    if((fd = open(path, O_WRONLY)) == -1){
        fprintf(stderr, "opening cpu.weight failed: %m\n");
        return -1;
    }
    if(write(fd, SHARES, strlen(SHARES)) == -1){
        fprintf(stderr, "writing cpu.weight failed: %m\n");
        close(fd);
        return -1;
    }
    close(fd);

    // PID LIMIT
    if(snprintf(path, sizeof(path), "%s/pids.max", dir) < 0){
        fprintf(stderr, "snprintf failed: %m\n");
        return -1;
    }
    if((fd = open(path, O_WRONLY)) == -1){
        fprintf(stderr, "opening pids.max failed: %m\n");
        return -1;
    }
    if(write(fd, PIDS, strlen(PIDS)) == -1){
        fprintf(stderr, "writing pids.max failed: %m\n");
        close(fd);
        return -1;
    }
    close(fd);

    // IO LIMIT
    if(snprintf(path, sizeof(path), "%s/io.weight", dir) < 0){
        fprintf(stderr, "snprintf failed: %m\n");
        return -1;
    }
    if((fd = open(path, O_WRONLY)) == -1){
        fprintf(stderr, "opening io.weight failed: %m\n");
        return -1;
    }
    if(write(fd, WEIGHT, strlen(WEIGHT)) == -1){
        fprintf(stderr, "writing io.weight failed: %m\n");
        close(fd);
        return -1;
    }
    close(fd);

    fprintf(stderr, "done.\n");

	return 0;
}

int assign_to_cgroups(pid_t child_pid, struct child_config *config){
    char path[PATH_MAX] = {0};
    int fd = 0;

    fprintf(stderr, "=> assigning child to cgroup...");

    if(snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.procs",
            config->hostname) < 0){
        fprintf(stderr, "snprintf failed: %m\n");
        return -1;
    }
    if((fd = open(path, O_WRONLY)) == -1){
        fprintf(stderr, "opening cgroup.procs failed: %m\n");
        return -1;
    }
    if(dprintf(fd, "%d\n", child_pid) == -1){
        fprintf(stderr, "writing pid to cgroup.procs failed: %m\n");
        close(fd);
        return -1;
    }
    close(fd);

    fprintf(stderr, "done.\n");
    return 0;
}

int free_resources(struct child_config *config){
    char dir[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    int fd = 0;

    if(!config->hostname) return 0;

    fprintf(stderr, "=> cleaning cgroup...");

    if((fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY)) == -1){
        fprintf(stderr, "opening root cgroup.procs failed: %m\n");
        return -1;
    }
    if(write(fd, "0", 1) == -1){
        fprintf(stderr, "writing to root cgroup.procs failed: %m\n");
        close(fd);
        return -1;
    }
    close(fd);

    if(snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s", config->hostname) < 0){
        fprintf(stderr, "snprintf failed: %m\n");
        return -1;
    }
    if(rmdir(dir)){
        fprintf(stderr, "rmdir %s failed: %m\n", dir);
        return -1;
    }

    fprintf(stderr, "done.\n");
    return 0;
}

int child(void *arg){
	struct child_config *config = arg;

fprintf(stderr, "[child] io_fd=%d config->fd=%d\n", config->io_fd, config->fd);
	
	if (sethostname(config->hostname, strlen(config->hostname))
	    || mounts(config)
	    || userns(config)
	    || capabilities()
	    || syscalls()) {
		close(config->fd);
		return -1;
	}
	if (close(config->fd)) {
		fprintf(stderr, "close failed: %m\n");
		return -1;
	}

    // SETTING FD LIMIT HERE TO ONLY CAP CHILD PROCESS
    fprintf(stderr, "=> setting rlimit...");
    if(setrlimit(RLIMIT_NOFILE,
          &(struct rlimit){
            .rlim_max = FD_COUNT,
            .rlim_cur = FD_COUNT,
          })){
        fprintf(stderr, "failed: %m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

	if (config->io_fd > 0) {
    dup2(config->io_fd, STDIN_FILENO);
    dup2(config->io_fd, STDOUT_FILENO);
    dup2(config->io_fd, STDERR_FILENO);
    close(config->io_fd);
}

	if (execve(config->argv[0], config->argv, NULL)) {
		fprintf(stderr, "execve failed! %m.\n");
		return -1;
	}
	return 0;
}

int userns(struct child_config *config){
	fprintf(stderr, "=> trying a user namespace...\n");
	int has_userns = !unshare(CLONE_NEWUSER);
	if(write(config->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)){
		fprintf(stderr, "couldn't write: %m\n");
		return -1;
	}
	int result = 0;
	if(read(config->fd, &result, sizeof(result)) != sizeof(result)){
		fprintf(stderr, "couldn't read: %m\n");
		return -1;
	}
	if(result) return -1;
	if(has_userns){
		fprintf(stderr, "done.\n");
	} else{
		fprintf(stderr, "unsupported? continuing.\n");
	}
	fprintf(stderr, "=> switching to uid %d / gid %d...\n", config->uid, config->uid);
	if(setgroups(1, & (gid_t) { config->uid }) ||
	    setresgid(config->uid, config->uid, config->uid) ||
	    setresuid(config->uid, config->uid, config->uid)) {
		fprintf(stderr, "%m\n");
		return -1;
	}
	fprintf(stderr, "done.\n");
	return 0;
}

int handle_child_uid_map(pid_t child_pid, int fd){
        int uid_map = 0;
        int has_userns = -1;

        if(read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)){
                fprintf(stderr, "couldnt read from child \n");
                return -1;
        }
        if(has_userns){
                char path[PATH_MAX] = {0};
                for(char **file = (char *[]){"uid_map", "gid_map", 0}; *file; file++){
                        if(snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file)
                                > sizeof(path)){
                                fprintf(stderr, "snprintf failed %m\n");
                                return -1;
                        }
                        fprintf(stderr, "Writing into buffer \n");
                        if((uid_map = open(path, O_WRONLY)) == -1){
                                fprintf(stderr, "open failed: %m\n");
                                return -1;
                        }
                        if(dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1){
                                fprintf(stderr, "dprintf failed: %m\n");
                                close(uid_map);
                                return -1;
                        }
                        close(uid_map);
                }
        }

        if(write(fd, &(int){0}, sizeof(int)) != sizeof(int)){
                fprintf(stderr, "write failed:%m \n");
                return -1;
        }

        return 0;
}

int choose_hostname(char* buff, size_t len){
        static const char *suits[] = { "swords", "wands", "pentacles", "cups" };
	static const char *minor[] = {
		"ace", "two", "three", "four", "five", "six", "seven", "eight",
		"nine", "ten", "page", "knight", "queen", "king"
	};
	static const char *major[] = {
		"fool", "magician", "high-priestess", "empress", "emperor",
		"hierophant", "lovers", "chariot", "strength", "hermit",
		"wheel", "justice", "hanged-man", "death", "temperance",
		"devil", "tower", "star", "moon", "sun", "judgment", "world"
	};

        int fd = open("/dev/urandom", O_RDONLY);
		unsigned long rnd = 0;
		read(fd, &rnd, sizeof(rnd));
		close(fd);

        size_t ix = rnd % 78;
        if(ix < sizeof(major)/sizeof(*major)){
                snprintf(buff, len, "%05lx-%s", rnd & 0xfffff, major[ix]);
        } else{
                ix -= sizeof(major)/sizeof(*major);
                snprintf(buff, len, 
                        "%05lxc-%s-of-%s", 
                        rnd & 0xfffff, 
                        minor[ix % (sizeof(minor)/sizeof(*minor))], 
                        suits[ix / sizeof(major) / sizeof(*major)]);
        }

        return 0;
}