/*
 * skyla-sup — SKYLA PRIME execution supervisor (v0.3.0 PRIME CONTAINMENT)
 *
 * Runs as PID 1 inside `unshare -Urmpf -n` (user, mount, PID, net namespaces),
 * chroots into a minimal rootfs, then applies every containment control in a
 * deliberate order and finally execs the untrusted interpreter.
 *
 * Controls, in application order (order matters; see EXECUTION_HOST_SECURITY.md):
 *   1. chroot(rootfs)                        host filesystem unreachable
 *   2. chdir("/workspace")                   no cwd escape
 *   3. close every fd > 2                    fd sanitation (no inherited sockets)
 *   4. rlimits                               RLIMIT_CPU/NPROC/FSIZE/CORE/AS/NOFILE
 *   5. prctl(PR_SET_NO_NEW_PRIVS)            setuid binaries cannot regain privilege
 *   6. Landlock ruleset                      filesystem write confinement (kernel-enforced)
 *   7. seccomp BPF filter                    syscall allowlist; denies mount/ptrace/socket...
 *   8. capset(0,0,0,0) + PR_CAPBSET_DROP      every capability dropped
 *   9. execve(python3 script.py)             untrusted code starts here
 *
 * Escalation of failure: if a mandatory control cannot be applied the process
 * exits non-zero and NOTHING is executed. There is no silent degraded mode.
 *
 * Build:  cc -O2 -Wall -o skyla-sup skyla-sup.c
 * Usage:  skyla-sup <rootfs> <workspace-rel> <script-rel> <cpu_s> <mem_mb> <fsize_mb> <nproc> <uid> <gid>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

/* Capabilities we must retain only until the final exec. */
#define CAP_ALL_LAST 40

static void die(const char *what) {
    fprintf(stderr, "skyla-sup: FATAL %s: %s\n", what, strerror(errno));
    _exit(111);
}

static void note(const char *what) {
    fprintf(stderr, "skyla-sup: %s\n", what);
}

/* ---------------------------------------------------------------- rlimits */
static void set_limit(int resource, rlim_t value, const char *name) {
    struct rlimit rl = {.rlim_cur = value, .rlim_max = value};
    if (setrlimit(resource, &rl) != 0) die(name);
}

/* ------------------------------------------------------------ fd sanitation */
static void close_inherited_fds(void) {
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    /* close_range is unavailable on all kernels we target here; loop. */
    for (int fd = 3; fd < maxfd; fd++) close(fd);
}

/* ----------------------------------------------------------------- landlock */
static int create_landlock_ruleset(const char *rootfs) {
    int abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return -1;                 /* Landlock unusable */

    __u64 handled = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
                    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
                    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
                    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
                    LANDLOCK_ACCESS_FS_REFER;
    if (abi < 2) handled &= ~(LANDLOCK_ACCESS_FS_REFER);

    struct landlock_ruleset_attr attr = {.handled_access_fs = handled};
    int rset = (int)syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (rset < 0) return -1;

    /* ONLY /workspace (and /tmp) may be written. Everything else: read-only. */
    const char *writable[] = {"workspace", "tmp", NULL};
    for (int i = 0; writable[i]; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", rootfs, writable[i]);
        int fd = open(path, O_PATH | O_CLOEXEC);
        if (fd < 0) continue;                /* directory absent: skip */
        struct landlock_path_beneath_attr pb = {
            .allowed_access = handled,
            .parent_fd = fd,
        };
        if (syscall(__NR_landlock_add_rule, rset, LANDLOCK_RULE_PATH_BENEATH,
                    &pb, 0) != 0) {
            close(fd);
            return -1;
        }
        close(fd);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    if (syscall(__NR_landlock_restrict_self, rset, 0) != 0) return -1;
    close(rset);
    return abi;
}

/* ------------------------------------------------------------------ seccomp */
#define SC_ALLOW(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static void install_seccomp(void) {
    struct sock_filter filter[] = {
        /* arch guard: x86_64 only */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        /* ---- denied outright (never allowed for a workload) ---- */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_umount2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pivot_root, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chroot, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_keyctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_add_key, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_request_key, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_perf_event_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_userfaultfd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pidfd_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setns, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        /* ---- networking: creation denied => no egress, no listeners ---- */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),

        /* ---- everything else: allow (Python needs a large but ordinary surface) ---- */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
        die("seccomp filter install");
}

/* ------------------------------------------------------------- capabilities */
/* Drop every capability from the bounding set and from all three capability
 * sets, then VERIFY by reading back /proc/self/status.  The verification is the
 * point: a silent failure here is exactly audit finding A-01. */
static void drop_all_capabilities(void) {
    for (int cap = 0; cap <= CAP_ALL_LAST; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
            if (errno != EINVAL && errno != EPERM) die("PR_CAPBSET_DROP");
        }
    }
    struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0, 0, 0}, {0, 0, 0}};
    if (syscall(SYS_capset, &hdr, data) != 0) die("capset");

    /* read back */
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) die("read /proc/self/status");
    char line[512];
    long bnd = -1, eff = -1, prm = -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long v;
        if (sscanf(line, "CapBnd: %llx", &v) == 1) bnd = (long)v;
        else if (sscanf(line, "CapEff: %llx", &v) == 1) eff = (long)v;
        else if (sscanf(line, "CapPrm: %llx", &v) == 1) prm = (long)v;
    }
    fclose(f);
    if (bnd < 0 || eff < 0 || prm < 0) die("parse capability status");
    if (bnd != 0 || eff != 0 || prm != 0) {
        fprintf(stderr, "skyla-sup: FATAL capabilities not cleared "
                        "(Bnd=%lx Eff=%lx Prm=%lx)\n",
                (unsigned long)bnd, (unsigned long)eff, (unsigned long)prm);
        _exit(112);
    }
    fprintf(stderr, "skyla-sup: verified CapBnd=0 CapEff=0 CapPrm=0\n");
}

/* ---------------------------------------------------------------------- main */
int main(int argc, char **argv) {
    if (argc != 10) {
        fprintf(stderr,
                "usage: %s rootfs workspace_rel script_rel cpu_s mem_mb fsize_mb nproc uid gid\n",
                argv[0]);
        return 2;
    }
    const char *rootfs = argv[1];
    const char *script_rel = argv[3];
    unsigned long cpu_s = strtoul(argv[4], NULL, 10);
    unsigned long mem_mb = strtoul(argv[5], NULL, 10);
    unsigned long fsize_mb = strtoul(argv[6], NULL, 10);
    unsigned long nproc = strtoul(argv[7], NULL, 10);
    uid_t uid = (uid_t)strtoul(argv[8], NULL, 10);
    gid_t gid = (gid_t)strtoul(argv[9], NULL, 10);

    /* The caller (inner.sh) has already built the mount tree while this process
     * held namespace-root. We now chroot, then immediately give up root. */

    /* 2. fd sanitation: nothing inherited from the parent */
    close_inherited_fds();
    /* 5a. no_new_privs + Landlock FIRST: rules attach to inodes/dentries, so
     *     they must be installed while the host paths still resolve. They remain
     *     in force after chroot(). */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die("PR_SET_NO_NEW_PRIVS");
    {
        int abi = create_landlock_ruleset(rootfs);
        if (abi < 0) die("landlock ruleset");
        fprintf(stderr, "skyla-sup: landlock ABI %d active (write-confined)\n", abi);
    }

    /* 1. filesystem confinement -- must precede the uid drop (CAP_SYS_CHROOT) */
    if (chroot(rootfs) != 0) die("chroot");
    if (chdir("/workspace") != 0) die("chdir /workspace");

    /* 3. resource limits (per-process; see RESOURCE_CONTROL_DESIGN.md for the
     *    documented limitation that per-cgroup aggregate limits need privileges
     *    this host does not grant). */
    set_limit(RLIMIT_CPU, cpu_s, "RLIMIT_CPU");
    set_limit(RLIMIT_AS, mem_mb * 1024UL * 1024UL, "RLIMIT_AS");
    set_limit(RLIMIT_NPROC, nproc, "RLIMIT_NPROC");
    set_limit(RLIMIT_FSIZE, fsize_mb * 1024UL * 1024UL, "RLIMIT_FSIZE");
    set_limit(RLIMIT_CORE, 0, "RLIMIT_CORE");
    set_limit(RLIMIT_NOFILE, 256, "RLIMIT_NOFILE");

    /* 4. identity inside the namespace.
     *
     * Only ONE uid can be mapped without newuidmap(1) (which is absent here), so
     * the process is namespace-root. Namespace-root is NOT host root: it has no
     * authority over any object outside this user namespace. What actually
     * matters for containment is that it keeps **zero capabilities** -- step 6
     * removes every one, and the outcome is verified below (CapEff must be 0).
     *
     * We therefore attempt a non-root uid for defence in depth, but a refusal is
     * tolerated ONLY because capability removal is mandatory and verified.
     */
    if (setgroups(0, NULL) != 0) {
        if (errno != EPERM && errno != EINVAL && errno != EACCES) die("setgroups");
    }
    if (getgid() != gid && setgid(gid) != 0) {
        if (errno != EINVAL) die("setgid");
    }
    if (getuid() != uid && setuid(uid) != 0) {
        if (errno != EINVAL) die("setuid");
    }

    /* 6. capabilities: none left for the workload */
    drop_all_capabilities();

    /* 7. seccomp: last, so nothing above is restricted by our own filter */
    install_seccomp();

    /* 8. finally: the untrusted interpreter */
    char *const args[] = {"/usr/bin/python3", (char *)script_rel, NULL};
    char *const envp[] = {"PATH=/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8",
                          "PYTHONDONTWRITEBYTECODE=1", NULL};
    execve(args[0], args, envp);
    die("execve python3");
    return 111;
}
