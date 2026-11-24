/*
 * mayhem/harnesses/replay_main.c - fuzz proot's syscall translation without ptrace.
 *
 * proot rewrites the syscalls of a traced guest: their number, six arguments and the guest memory
 * those arguments point to (paths, sockaddrs, msghdrs, ELF files named by execve, ...). Tracing a
 * real child needs ptrace, which the Mayhem fuzzing sandbox does not allow (the earlier targets
 * that ran the real proot over a guest program never started there: 0 edges). So this harness
 * gives proot a simulated tracee, as savantenvs/strace does for strace:
 *
 *  - proot's own main (renamed proot_main by build.sh) parses the real command line, so every
 *    option (-0, -l, -k, -p, -b, --sysvipc ...) configures the tracee and its extensions exactly
 *    as in a normal run;
 *  - launch_process/event_loop are redirected (objcopy, cli.o only) here: instead of forking a
 *    guest, the input's syscall records are replayed through proot's own translate_syscall()
 *    entry and exit stages, which run every path translation, extension and execve handler;
 *  - ptrace and process_vm_readv/writev in proot's objects are redirected to fz_* below: the
 *    registers are a struct in this process, and "guest memory" is an arena at a fixed address
 *    holding the input (plus a stack area proot may write below the stack pointer); every other
 *    address faults (EFAULT), like an unmapped page.
 *  - the guest pid is this process, so the descriptors proot inspects through /proc/<pid>/fd are
 *    real ones opened below (pipe, socketpair, eventfd, a deleted file, netlink, /dev/null).
 *  - proot itself makes real host calls on translated paths from the records (link2symlink's
 *    rename/symlink/unlink, fake_id0's chmod and meta files, socket aliases, kept bound files),
 *    so each input gets a fresh scratch tree: the guest root (-r, a few files copied from the
 *    image), proot's temporary directory (PROOT_TMP_DIR) and the cwd. No input can change a file
 *    another input sees. The tree is a reused slot, <TMPDIR>/proot-replay-slot-N, claimed by a
 *    flock on <TMPDIR>/proot-replay-slot-N.lock (see claim_slot()): a sanitizer abort, a signal
 *    or the engine's SIGKILL on a timeout skip exit handlers, so the next claimer of a slot
 *    empties it first, and the trees on disk never outnumber the NSLOTS slots. A process
 *    starts its search at the slot of its pid, so claiming costs one flock. The guest programs' bytes are read once, in a constructor that runs before
 *    AFL's forkserver (early_setup()). Guest programs are copied as their first page
 *    and dynamic section plus a hole (put_file()), so a
 *    tree takes tens of KB. "@SCRATCH@" at the start of an option is replaced
 *    with the scratch directory (e.g. -b @SCRATCH@/bound:/mnt).
 *
 * Usage:  proot-replay <mode> <input> [proot options...]
 * runs    proot_main("proot", "-r", <scratch>/root, "-b", "/proc", "-w", "/", [proot options...],
 *         "/bin/true") and
 *         replays <input>.
 *
 * Input layout:
 *   byte 0   flags: bit0 = syscalls fail with the record's result (else they return 0, unless
 *            a path argument is unreadable or empty: the kernel always fails those, so they
 *            return -EFAULT/-ENOENT as it would)
 *   byte 1   number of records (at most 32)
 *   records  { u16 nr; u64 arg[6]; u64 result; }  (little endian, 58 bytes each)
 *   rest     free data the arguments may point into
 * An argument whose top byte is 0xff becomes a pointer into the arena: ARENA + (low 32 bits %
 * input size). Modes restrict nr to a syscall family. Like real proot, every replay starts with
 * the execve() of the guest program (/bin/true), which sets up tracee->load_info. Mode "exec"
 * instead treats the whole input as that program: it is copied to an executable scratch file
 * that the single execve() names.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <ftw.h>
#include <sys/file.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <linux/netlink.h>
#include <unistd.h>

#include "tracee/tracee.h"
#include "syscall/syscall.h"

int proot_main(int argc, char *const argv[]);

#define ARENA     0x300000000000UL /* ASan HighMem, clear of its shadow and allocator */
#define ARENA_SZ  (8UL << 20)
#define MAXIN     (1UL << 20)
#define REC       58
#define NREC_MAX  32
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const long t_path[] = {
	__NR_open, __NR_openat, __NR_stat, __NR_lstat, __NR_newfstatat, __NR_statx, __NR_access,
	__NR_faccessat, __NR_faccessat2, __NR_readlink, __NR_readlinkat, __NR_chdir, __NR_fchdir,
	__NR_getcwd, __NR_rename, __NR_renameat, __NR_renameat2, __NR_mkdir, __NR_mkdirat,
	__NR_rmdir, __NR_unlink, __NR_unlinkat, __NR_link, __NR_linkat, __NR_symlink,
	__NR_symlinkat, __NR_truncate, __NR_chmod, __NR_fchmodat, __NR_chown, __NR_lchown,
	__NR_fchownat, __NR_utimensat, __NR_mknod, __NR_mknodat, __NR_mount, __NR_umount2,
	__NR_chroot, __NR_getdents64, __NR_brk, __NR_prlimit64, __NR_uname, __NR_execveat,
	__NR_name_to_handle_at, __NR_inotify_add_watch, __NR_statfs, __NR_getxattr,
	__NR_setxattr, __NR_listxattr, __NR_openat2, __NR_creat, __NR_fstat,
};
static const long t_id[] = {
	__NR_sendmsg, __NR_fstat, __NR_newfstatat, __NR_stat, __NR_lstat, __NR_statx,
	__NR_chown, __NR_fchown, __NR_lchown, __NR_fchownat, __NR_chmod, __NR_fchmod,
	__NR_fchmodat, __NR_mknod, __NR_mknodat, __NR_setuid, __NR_setgid, __NR_setreuid,
	__NR_setregid, __NR_setresuid, __NR_setresgid, __NR_getresuid, __NR_getresgid,
	__NR_setfsuid, __NR_setfsgid, __NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,
	__NR_capset, __NR_capget, __NR_getsockopt, __NR_access, __NR_faccessat, __NR_execve,
	__NR_mkdir, __NR_openat, __NR_setgroups, __NR_getgroups, __NR_recvmsg,
};
static const long t_socket[] = {
	__NR_socket, __NR_bind, __NR_connect, __NR_sendto, __NR_sendmsg, __NR_recvmsg,
	__NR_recvfrom, __NR_getsockname, __NR_getpeername, __NR_accept, __NR_accept4,
	__NR_getsockopt, __NR_setsockopt, __NR_sendmmsg, __NR_recvmmsg, __NR_socketpair,
	__NR_close, __NR_listen,
};
static const long t_link[] = {
	__NR_link, __NR_linkat, __NR_symlink, __NR_symlinkat, __NR_unlink, __NR_unlinkat,
	__NR_rename, __NR_renameat, __NR_renameat2, __NR_stat, __NR_lstat, __NR_newfstatat,
	__NR_statx, __NR_fstat, __NR_readlink, __NR_readlinkat, __NR_getdents64, __NR_open,
	__NR_openat, __NR_chmod, __NR_fchmodat, __NR_truncate, __NR_utimensat,
};
static const long t_ipc[] = {
	__NR_shmget, __NR_shmat, __NR_shmdt, __NR_shmctl, __NR_msgget, __NR_msgsnd, __NR_msgrcv,
	__NR_msgctl, __NR_semget, __NR_semop, __NR_semtimedop, __NR_semctl, __NR_memfd_create,
	__NR_ioctl, __NR_mmap, __NR_munmap, __NR_ftruncate, __NR_close,
};

struct mode {
	const char *name;
	const long *tab;
	size_t n;
};
static const struct mode modes[] = {
	{ "syscall", NULL, 0 },
	{ "path", t_path, ARRAY_SIZE(t_path) },
	{ "id", t_id, ARRAY_SIZE(t_id) },
	{ "socket", t_socket, ARRAY_SIZE(t_socket) },
	{ "link", t_link, ARRAY_SIZE(t_link) },
	{ "ipc", t_ipc, ARRAY_SIZE(t_ipc) },
	{ "exec", NULL, 0 },
};

static const struct mode *mode;
static const char *in_path;
static unsigned char *arena;
static size_t in_len;
static struct user_regs_struct fz_regs;
static Tracee *fz_tracee;
static char exec_path[64];
static char scratch[256];      /* this process's scratch tree (a claimed slot) */
static char scratch_lock[256]; /* the flock'ed file that marks the slot taken */

/* ---- simulated guest memory ---------------------------------------------------------------- */

static int in_arena(unsigned long addr, size_t len)
{
	return addr >= ARENA && len <= ARENA_SZ && addr - ARENA <= ARENA_SZ - len;
}

static ssize_t fz_vm(const struct iovec *local, unsigned long liovcnt,
		     const struct iovec *remote, unsigned long riovcnt, int write)
{
	/* proot only ever uses one remote iovec; the local side may be scattered.  */
	if (riovcnt != 1) {
		errno = EINVAL;
		return -1;
	}
	unsigned long addr = (unsigned long) remote[0].iov_base;
	size_t want = remote[0].iov_len, done = 0;
	if (!in_arena(addr, 0)) {
		errno = EFAULT;
		return -1;
	}
	size_t avail = ARENA_SZ - (addr - ARENA);
	if (want > avail)
		want = avail; /* short transfer at the end of the mapping */
	for (unsigned long i = 0; i < liovcnt && done < want; i++) {
		size_t n = local[i].iov_len;
		if (n > want - done)
			n = want - done;
		if (write)
			memcpy(arena + (addr - ARENA) + done, local[i].iov_base, n);
		else
			memcpy(local[i].iov_base, arena + (addr - ARENA) + done, n);
		done += n;
	}
	if (done == 0 && want != 0) {
		errno = EFAULT;
		return -1;
	}
	return (ssize_t) done;
}

ssize_t fz_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long liovcnt,
			    const struct iovec *remote, unsigned long riovcnt, unsigned long flags)
{
	(void) pid; (void) flags;
	return fz_vm(local, liovcnt, remote, riovcnt, 0);
}

ssize_t fz_process_vm_writev(pid_t pid, const struct iovec *local, unsigned long liovcnt,
			     const struct iovec *remote, unsigned long riovcnt, unsigned long flags)
{
	(void) pid; (void) flags;
	return fz_vm(local, liovcnt, remote, riovcnt, 1);
}

long fz_ptrace(int request, ...)
{
	va_list ap;
	va_start(ap, request);
	pid_t pid = va_arg(ap, pid_t);
	void *addr = va_arg(ap, void *);
	void *data = va_arg(ap, void *);
	va_end(ap);
	(void) pid;

	errno = 0;
	switch (request) {
	case PTRACE_GETREGS:
		memcpy(data, &fz_regs, sizeof(fz_regs));
		return 0;
	case PTRACE_SETREGS:
		memcpy(&fz_regs, data, sizeof(fz_regs));
		return 0;
	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET: {
		struct iovec *iov = data;
		size_t n = iov->iov_len < sizeof(fz_regs) ? iov->iov_len : sizeof(fz_regs);
		if (request == PTRACE_GETREGSET)
			memcpy(iov->iov_base, &fz_regs, n);
		else
			memcpy(&fz_regs, iov->iov_base, n);
		iov->iov_len = n;
		return 0;
	}
	case PTRACE_PEEKDATA:
	case PTRACE_PEEKTEXT: {
		long word;
		if (!in_arena((unsigned long) addr, sizeof(word))) {
			errno = EFAULT;
			return -1;
		}
		memcpy(&word, arena + ((unsigned long) addr - ARENA), sizeof(word));
		return word;
	}
	case PTRACE_POKEDATA:
	case PTRACE_POKETEXT: {
		long word = (long) data;
		if (!in_arena((unsigned long) addr, sizeof(word))) {
			errno = EFAULT;
			return -1;
		}
		memcpy(arena + ((unsigned long) addr - ARENA), &word, sizeof(word));
		return 0;
	}
	case PTRACE_GETEVENTMSG:
		if (data)
			*(unsigned long *) data = 0;
		return 0;
	case PTRACE_GETSIGMASK:
		if (data)
			memset(data, 0, (size_t) addr);
		return 0;
	default:
		/* CONT/SYSCALL/SETOPTIONS/...: the simulated tracee obeys silently.  */
		return 0;
	}
}

/* The guest pid is this process: never signal it, never spawn helpers.  */
int fz_kill(pid_t pid, int sig) { (void) pid; (void) sig; return 0; }
pid_t fz_fork(void) { errno = EAGAIN; return -1; }

/* ---- replay ---------------------------------------------------------------------------------- */

static uint64_t le(const unsigned char *p, int n)
{
	uint64_t v = 0;
	for (int i = n - 1; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

static word_t arg_value(uint64_t a)
{
	if ((a >> 56) == 0xff && in_len > 0)
		return (word_t) (ARENA + (a & 0xffffffffUL) % in_len);
	return (word_t) a;
}

/* Path arguments the kernel resolves, per syscall (x86_64): the argument indices of the paths
 * and, for the *at calls that take AT_EMPTY_PATH, the index of their flags argument (-1: none).
 * A path the kernel cannot read fails with EFAULT, and an empty one with ENOENT (unless
 * AT_EMPTY_PATH); those calls never succeed on a real kernel, so the harness must not report
 * success for them either: proot's exit stage only runs its post-processing (rename's
 * compare_paths, link2symlink, ...) on a successful result.  */
struct path_args {
	long nr;
	signed char path[2];
	signed char flags;
};
static const struct path_args path_args[] = {
	{ __NR_open, { 0, -1 }, -1 },          { __NR_creat, { 0, -1 }, -1 },
	{ __NR_stat, { 0, -1 }, -1 },          { __NR_lstat, { 0, -1 }, -1 },
	{ __NR_access, { 0, -1 }, -1 },        { __NR_readlink, { 0, -1 }, -1 },
	{ __NR_chdir, { 0, -1 }, -1 },         { __NR_rename, { 0, 1 }, -1 },
	{ __NR_mkdir, { 0, -1 }, -1 },         { __NR_rmdir, { 0, -1 }, -1 },
	{ __NR_unlink, { 0, -1 }, -1 },        { __NR_link, { 0, 1 }, -1 },
	{ __NR_symlink, { 0, 1 }, -1 },        { __NR_truncate, { 0, -1 }, -1 },
	{ __NR_chmod, { 0, -1 }, -1 },         { __NR_chown, { 0, -1 }, -1 },
	{ __NR_lchown, { 0, -1 }, -1 },        { __NR_mknod, { 0, -1 }, -1 },
	{ __NR_chroot, { 0, -1 }, -1 },        { __NR_statfs, { 0, -1 }, -1 },
	{ __NR_getxattr, { 0, -1 }, -1 },      { __NR_setxattr, { 0, -1 }, -1 },
	{ __NR_listxattr, { 0, -1 }, -1 },     { __NR_lgetxattr, { 0, -1 }, -1 },
	{ __NR_lsetxattr, { 0, -1 }, -1 },     { __NR_llistxattr, { 0, -1 }, -1 },
	{ __NR_removexattr, { 0, -1 }, -1 },   { __NR_lremovexattr, { 0, -1 }, -1 },
	{ __NR_utime, { 0, -1 }, -1 },         { __NR_utimes, { 0, -1 }, -1 },
	{ __NR_execve, { 0, -1 }, -1 },        { __NR_umount2, { 0, -1 }, -1 },
	{ __NR_pivot_root, { 0, 1 }, -1 },     { __NR_inotify_add_watch, { 1, -1 }, -1 },
	{ __NR_openat, { 1, -1 }, -1 },        { __NR_openat2, { 1, -1 }, -1 },
	{ __NR_newfstatat, { 1, -1 }, 3 },     { __NR_statx, { 1, -1 }, 2 },
	{ __NR_faccessat, { 1, -1 }, -1 },     { __NR_faccessat2, { 1, -1 }, 3 },
	{ __NR_readlinkat, { 1, -1 }, -1 },    { __NR_renameat, { 1, 3 }, -1 },
	{ __NR_renameat2, { 1, 3 }, -1 },      { __NR_mkdirat, { 1, -1 }, -1 },
	{ __NR_unlinkat, { 1, -1 }, -1 },      { __NR_linkat, { 1, 3 }, 4 },
	{ __NR_symlinkat, { 0, 2 }, -1 },      { __NR_fchmodat, { 1, -1 }, -1 },
	{ __NR_fchownat, { 1, -1 }, 4 },       { __NR_mknodat, { 1, -1 }, -1 },
	{ __NR_execveat, { 1, -1 }, 4 },       { __NR_name_to_handle_at, { 1, -1 }, 4 },
	{ __NR_futimesat, { 1, -1 }, -1 },
	/* utimensat accepts a NULL path (it then works on the dirfd): not listed.  */
};

static word_t reg_arg(int i)
{
	switch (i) {
	case 0: return fz_regs.rdi;
	case 1: return fz_regs.rsi;
	case 2: return fz_regs.rdx;
	case 3: return fz_regs.r10;
	case 4: return fz_regs.r8;
	default: return fz_regs.r9;
	}
}

/* The error the kernel is guaranteed to return for the syscall in fz_regs as proot left it after
 * its entry stage (the registers the kernel would see), or 0 when it may succeed.  */
static long kernel_path_error(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(path_args); i++) {
		const struct path_args *pa = &path_args[i];
		if (pa->nr != (long) fz_regs.orig_rax)
			continue;
		for (int j = 0; j < 2 && pa->path[j] >= 0; j++) {
			unsigned long addr = reg_arg(pa->path[j]);
			if (!in_arena(addr, 1))
				return -EFAULT;
			size_t max = ARENA_SZ - (addr - ARENA);
			const char *str = (const char *) arena + (addr - ARENA);
			size_t len = strnlen(str, max);
			if (len == max)
				return -EFAULT; /* runs off the end of the mapping */
			if (len == 0) {
				int empty_ok = pa->flags >= 0 && (reg_arg(pa->flags) & AT_EMPTY_PATH)
					       && (pa->nr != __NR_linkat || j == 0);
				if (!empty_ok)
					return -ENOENT;
			}
		}
		return 0;
	}
	return 0;
}

/* One syscall stop pair: the kernel's view of entry, then (if proot asked for it) the exit.  */
static void stop_pair(long nr, const word_t args[6], long result)
{
	fz_regs.orig_rax = nr;
	fz_regs.rax = -ENOSYS;
	fz_regs.rdi = args[0];
	fz_regs.rsi = args[1];
	fz_regs.rdx = args[2];
	fz_regs.r10 = args[3];
	fz_regs.r8 = args[4];
	fz_regs.r9 = args[5];

	fz_tracee->status = 0;
	fz_tracee->restart_how = PTRACE_SYSCALL;
	fz_tracee->regs_fetched_at_stop = false;
	translate_syscall(fz_tracee); /* sysenter */

	if (fz_tracee->status == 0)
		return; /* no sysexit stop requested */

	if (fz_tracee->status < 0)
		result = fz_tracee->status;
	else if (result >= 0) {
		long err = kernel_path_error();
		if (err < 0)
			result = err; /* the kernel would have failed it */
	}
	fz_regs.rax = result;
	fz_tracee->regs_fetched_at_stop = false;
	translate_syscall(fz_tracee); /* sysexit */
}

/* The execve() stop: path, argv = { path, NULL }, envp = { NULL } placed after the input, where
 * no fuzzed pointer argument can point (arg_value() wraps offsets modulo the input length).  */
#define INITIAL_PROGRAM "/bin/true"
static int guest_execve(const char *path)
{
	word_t args[6];
	size_t off = (in_len + 15) & ~15UL;

	if (off + 256 > ARENA_SZ / 2 || strlen(path) >= 128)
		return 0;
	strcpy((char *) arena + off, path);
	word_t argv_addr = ARENA + off + 128;
	word_t path_addr = ARENA + off;
	memcpy(arena + off + 128, &path_addr, sizeof(path_addr));
	memset(arena + off + 136, 0, 16);
	args[0] = path_addr;
	args[1] = argv_addr;
	args[2] = argv_addr + 8;
	args[3] = args[4] = args[5] = 0;
	stop_pair(__NR_execve, args, 0);
	/* Clear it again so the records see the same arena whatever the input length.  */
	memset(arena + off, 0, 256);
	return 1;
}

static void replay(void)
{
	word_t args[6];

	fz_regs.cs = 0x33; /* 64-bit code segment */
	fz_regs.ss = 0x2b;
	fz_regs.rip = ARENA + ARENA_SZ - 2 * 4096;
	fz_regs.rsp = ARENA + ARENA_SZ - 4 * 4096;

	/* Real proot's first stop for every tracee is the execve() of the guest program
	 * (launch_process() execvp()s it), and translating it is what sets up tracee->load_info.
	 * Mode "exec" makes that execve name the input itself; every other mode execs a fixed
	 * program from the image first, so the fuzzed records start from the state real proot
	 * reaches, not from a tracee that never exec'd.  */
	if (!guest_execve(strcmp(mode->name, "exec") == 0 ? exec_path : INITIAL_PROGRAM))
		return;
	if (strcmp(mode->name, "exec") == 0)
		return;

	if (in_len < 2)
		return;
	unsigned flags = arena[0];
	unsigned nrec = arena[1] % (NREC_MAX + 1);
	for (unsigned r = 0; r < nrec && 2 + (r + 1) * REC <= in_len; r++) {
		const unsigned char *p = arena + 2 + r * REC;
		uint16_t raw = (uint16_t) le(p, 2);
		long nr = mode->tab ? mode->tab[raw % mode->n] : (long) (raw % 460);
		if (nr == __NR_exit || nr == __NR_exit_group || nr == __NR_vfork
		    || nr == __NR_fork || nr == __NR_clone || nr == __NR_clone3)
			continue;
		for (int i = 0; i < 6; i++)
			args[i] = arg_value(le(p + 2 + 8 * i, 8));
		long result = (flags & 1) ? -(long) (le(p + 50, 8) % 134) : 0;

		stop_pair(nr, args, result);

		/* Syscalls proot chained after this one: each gets its own stop pair.  */
		for (int c = 0; c < 8 && fz_tracee->chain.syscalls != NULL; c++) {
			word_t cargs[6] = { fz_regs.rdi, fz_regs.rsi, fz_regs.rdx,
					    fz_regs.r10, fz_regs.r8, fz_regs.r9 };
			stop_pair((long) fz_regs.rax, cargs, 0);
		}
		if (fz_tracee->chain.syscalls != NULL) {
			TALLOC_FREE(fz_tracee->chain.syscalls);
		}
	}
}

/* Called from proot_main in place of launch_process(): the tracee is this process.  */
int fz_launch_process(Tracee *tracee, char *const argv[])
{
	(void) argv;
	fz_tracee = tracee;
	tracee->pid = getpid();
	return 0;
}

/* Called from proot_main in place of event_loop().  */
int fz_event_loop(void)
{
	if (fz_tracee != NULL)
		replay();
	return 0;
}

static void open_fd_pool(void)
{
	int p[2], s[2];
	char tmpl[512];

	if (pipe(p) == 0) { /* fds 3, 4 */ }
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0) { /* 5, 6 */ }
	(void) eventfd(0, 0);
	snprintf(tmpl, sizeof(tmpl), "%s/tmp/deleted-XXXXXX", scratch);
	int d = mkstemp(tmpl);
	if (d >= 0)
		unlink(tmpl); /* a "(deleted)" descriptor */
	(void) socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	(void) open("/dev/null", O_RDWR);
	(void) open(".", O_RDONLY | O_DIRECTORY);
}

/* ---- per-input scratch tree ---------------------------------------------------------------- */

/* A guest program copied from the image: proot only reads its ELF header, program headers and
 * PT_INTERP string (all in the first page) and its dynamic section (ldso.c's DT_RPATH/RUNPATH
 * lookup; these binaries have neither, so no string table is read). The simulated tracee maps
 * nothing. So only those ranges are copied and the rest is a hole of the original size: the copy
 * reads the same to proot and takes a few KB of the TMPDIR file system, not the whole binary.  */
#define COPY_HEAD 4096
#define COPY_MAX  (4UL << 20)
struct image_file {
	const char *rel, *host;
	unsigned char *data; /* the copied ranges, at their file offsets (a hole elsewhere) */
	size_t data_len;     /* bytes of data held: the head, then up to the dynamic section's end */
	off_t size;          /* the original file size */
};
static struct image_file image_files[] = {
	{ "root/bin/true", "/bin/true", NULL, 0, 0 },
	{ "root/bin/sh", "/bin/sh", NULL, 0, 0 },
	{ "root/usr/bin/env", "/usr/bin/env", NULL, 0, 0 },
	{ "root/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", NULL, 0, 0 },
};

/* Read the ranges of an image file that put_file() copies, once per process (before the
 * forkserver, so every input of an AFL engine reuses them): the first page, and the dynamic
 * section with zeros in between (written back as a hole when they are zero).  */
static void load_image_file(struct image_file *f)
{
	int in = open(f->host, O_RDONLY);
	struct stat st;
	if (in < 0)
		return;
	if (fstat(in, &st) == 0 && (f->data = calloc(1, COPY_MAX)) != NULL) {
		ssize_t n = pread(in, f->data, COPY_HEAD, 0);
		f->size = st.st_size;
		f->data_len = n > 0 ? (size_t) n : 0;
		const Elf64_Ehdr *eh = (const Elf64_Ehdr *) f->data;
		if (n >= (ssize_t) sizeof(*eh) && memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0
		    && eh->e_phentsize == sizeof(Elf64_Phdr)
		    && eh->e_phoff + (uint64_t) eh->e_phnum * sizeof(Elf64_Phdr) <= (uint64_t) n) {
			for (int i = 0; i < eh->e_phnum; i++) {
				Elf64_Phdr ph;
				memcpy(&ph, f->data + eh->e_phoff + i * sizeof(ph), sizeof(ph));
				if (ph.p_type != PT_DYNAMIC || ph.p_offset >= COPY_MAX
				    || ph.p_filesz > COPY_MAX - ph.p_offset)
					continue;
				ssize_t r = pread(in, f->data + ph.p_offset, ph.p_filesz, (off_t) ph.p_offset);
				if (r > 0 && ph.p_offset + (size_t) r > f->data_len)
					f->data_len = ph.p_offset + (size_t) r;
			}
		}
	}
	close(in);
}

static void put_file(const char *rel, const struct image_file *img, const char *text)
{
	char path[512];
	snprintf(path, sizeof(path), "%s/%s", scratch, rel);
	int out = open(path, O_WRONLY | O_CREAT | O_EXCL, 0755);
	if (out < 0)
		return;
	if (text != NULL) {
		if (write(out, text, strlen(text)) < 0) { /* best effort */ }
	} else if (img->data != NULL) {
		/* Page by page, skipping all-zero pages so they stay holes.  */
		static const unsigned char zero[COPY_HEAD];
		for (size_t off = 0; off < img->data_len; off += COPY_HEAD) {
			size_t n = img->data_len - off < COPY_HEAD ? img->data_len - off : COPY_HEAD;
			if (memcmp(img->data + off, zero, n) != 0
			    && pwrite(out, img->data + off, n, (off_t) off) < 0) { /* best effort */ }
		}
		if (ftruncate(out, img->size) < 0) { /* best effort */ }
	}
	close(out);
}

static void remove_tree(const char *path);

/* Claim a scratch slot: <TMPDIR>/proot-replay-slot-N (the tree) belongs to whichever process
 * holds a flock on <TMPDIR>/proot-replay-slot-N.lock. The kernel releases that lock however the
 * process ends (exit, sanitizer abort, signal, the engine's SIGKILL on a timeout), so the next
 * process to claim the slot first removes whatever a dead owner left there. Lock files are never
 * unlinked (no create/unlink race). The search starts at the slot of the process's pid (and
 * wraps), so a claim normally takes one open+flock however many processes run at once (a
 * lowest-first search costs one per busy slot, on every input); at most NSLOTS trees of a
 * dead owner can be left on disk, each tens of KB, however many inputs crash or time out.  */
#define NSLOTS 1024
static int claim_slot(const char *tmp)
{
	for (int k = 0, i; k < NSLOTS; k++) {
		i = (int) (((unsigned) getpid() + (unsigned) k) % NSLOTS);
		snprintf(scratch_lock, sizeof(scratch_lock), "%s/proot-replay-slot-%d.lock", tmp, i);
		int fd = open(scratch_lock, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (fd < 0)
			return -1;
		if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
			/* Held until the process ends; the descriptor sits above the fd pool.  */
			int high = fcntl(fd, F_DUPFD_CLOEXEC, 200);
			close(fd);
			if (high < 0)
				return -1;
			snprintf(scratch, sizeof(scratch), "%s/proot-replay-slot-%d", tmp, i);
			remove_tree(scratch); /* a dead owner's leftovers */
			if (mkdir(scratch, 0700) == 0)
				return 0;
			close(high); /* could not be emptied: leave it, try the next slot */
			continue;
		}
		int err = errno;
		close(fd);
		if (err != EWOULDBLOCK) {
			/* No working flock here: fall back to a tree named after this pid, which no
			 * live process can own; remove what a dead process with the same pid left.  */
			snprintf(scratch, sizeof(scratch), "%s/proot-replay-pid-%d", tmp, (int) getpid());
			scratch_lock[0] = '\0';
			remove_tree(scratch);
			return mkdir(scratch, 0700);
		}
	}
	return -1;
}

/* Fill this process's slot with a fresh tree for one input: whatever the previous input (or a
 * dead owner) left is removed first.  */
static int make_scratch(void)
{
	static const char *const dirs[] = {
		"root", "root/bin", "root/usr", "root/usr/bin", "root/lib64", "root/etc", "root/tmp",
		"root/dev", "root/proc", "root/mnt", "tmp", "bound", "bound/dir",
	};

	remove_tree(scratch);
	if (mkdir(scratch, 0700) < 0)
		return -1;
	for (size_t i = 0; i < ARRAY_SIZE(dirs); i++) {
		char path[512];
		snprintf(path, sizeof(path), "%s/%s", scratch, dirs[i]);
		if (mkdir(path, 0755) < 0)
			return -1;
	}
	/* Guest programs the replays and seeds name (the initial execve, shebang interpreters)
	 * and their ELF interpreter: copies, never links, as proot may chmod or rename them.  */
	for (size_t i = 0; i < ARRAY_SIZE(image_files); i++)
		put_file(image_files[i].rel, &image_files[i], NULL);
	put_file("root/etc/passwd", NULL, "root:x:0:0:root:/root:/bin/sh\n");
	put_file("root/etc/hostname", NULL, "guest\n");
	put_file("root/dev/null", NULL, "");
	put_file("bound/file", NULL, "bound\n");

	char path[512];
	snprintf(path, sizeof(path), "%s/tmp", scratch);
	setenv("PROOT_TMP_DIR", path, 1);
	snprintf(path, sizeof(path), "%s/root", scratch);
	return chdir(path); /* relative guest paths and the "." descriptor stay inside */
}

static int unreadable_dirs;

static int unlock_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	(void) ftw;
	if (type == FTW_DNR)
		unreadable_dirs++; /* nftw did not descend into it: another pass will */
	if ((type == FTW_D || type == FTW_DNR) && (st->st_mode & 0700) != 0700)
		(void) chmod(path, 0700); /* fake_id0 may have chmod'ed it 000 */
	return 0;
}

static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	(void) st; (void) ftw;
	(void) (type == FTW_DP ? rmdir(path) : unlink(path));
	return 0;
}

static void remove_tree(const char *path)
{
	struct stat st;
	if (lstat(path, &st) < 0)
		return; /* nothing there (the previous input's exit removed it) */
	/* One removal pass is enough unless an input left a directory proot chmod'ed (fake_id0)
	 * without search or write permission for its owner.  */
	(void) nftw(path, remove_entry, 16, FTW_PHYS | FTW_MOUNT | FTW_DEPTH);
	if (lstat(path, &st) < 0)
		return;
	/* Each pass opens the directories the previous one made readable (nested mode-000
	 * directories need one pass per level).  */
	for (int pass = 0; pass < 64; pass++) {
		unreadable_dirs = 0;
		if (nftw(path, unlock_entry, 16, FTW_PHYS | FTW_MOUNT) != 0 || unreadable_dirs == 0)
			break;
	}
	(void) nftw(path, remove_entry, 16, FTW_PHYS | FTW_MOUNT | FTW_DEPTH);
}

static void remove_scratch(void)
{
	if (scratch[0] == '\0')
		return;
	if (chdir("/") < 0) { /* removal works from anywhere */ }
	remove_tree(scratch); /* the slot's lock file stays, for the next process to claim */
	scratch[0] = '\0';
}

/* Once per process, before AFL's forkserver starts (its constructor runs at a later priority,
 * and forks every input from there): read the guest programs' bytes, which do not depend on
 * the input, so each input's put_file() only writes them.  */
__attribute__((constructor(1))) static void early_setup(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(image_files); i++)
		load_image_file(&image_files[i]);
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <mode> <input> [proot options...]\n", argv[0]);
		return 2;
	}
	for (size_t i = 0; i < ARRAY_SIZE(modes); i++)
		if (strcmp(argv[1], modes[i].name) == 0)
			mode = &modes[i];
	if (mode == NULL) {
		fprintf(stderr, "unknown mode %s\n", argv[1]);
		return 2;
	}
	in_path = argv[2];

	arena = mmap((void *) ARENA, ARENA_SZ, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (arena == MAP_FAILED || arena != (unsigned char *) ARENA) {
		perror("mmap arena");
		return 2;
	}

	FILE *f = fopen(in_path, "rb");
	if (f == NULL) {
		perror(in_path);
		return 2;
	}
	in_len = fread(arena, 1, MAXIN, f);
	fclose(f);

	const char *tmp = getenv("TMPDIR");
	if (tmp == NULL || tmp[0] == '\0')
		tmp = "/tmp";
	if (claim_slot(tmp) < 0 || make_scratch() < 0) {
		perror("scratch tree");
		remove_scratch();
		return 2;
	}
	atexit(remove_scratch); /* proot may exit() from inside proot_main */

	if (strcmp(mode->name, "exec") == 0) {
		/* proot checks the program is executable: an +x copy at the guest path /prog.  */
		char host[512];
		snprintf(exec_path, sizeof(exec_path), "/prog");
		snprintf(host, sizeof(host), "%s/root/prog", scratch);
		int fd = open(host, O_WRONLY | O_CREAT | O_EXCL, 0755);
		if (fd < 0) {
			perror(host);
			return 2;
		}
		if (write(fd, arena, in_len) != (ssize_t) in_len) { /* best effort */ }
		close(fd);
	} else {
		open_fd_pool();
	}

	char root[512];
	snprintf(root, sizeof(root), "%s/root", scratch);
	char **pargv = calloc((size_t) argc + 8, sizeof(char *));
	int pargc = 0;
	pargv[pargc++] = "proot";
	pargv[pargc++] = "-r";
	pargv[pargc++] = root;
	/* The guest sees the host's /proc, as it did with the host as its root; proot substitutes
	 * /proc/<pid>/{root,cwd,exe} with guest values, and the fds point into the scratch tree.  */
	pargv[pargc++] = "-b";
	pargv[pargc++] = "/proc";
	pargv[pargc++] = "-w"; /* the guest starts in its root, the harness's cwd */
	pargv[pargc++] = "/";
	for (int i = 3; i < argc; i++) {
		const char *opt = argv[i];
		if (strncmp(opt, "@SCRATCH@", 9) == 0) {
			size_t n = strlen(scratch) + strlen(opt) + 1;
			char *o = malloc(n);
			snprintf(o, n, "%s%s", scratch, opt + 9);
			opt = o;
		}
		pargv[pargc++] = (char *) opt;
	}
	pargv[pargc++] = INITIAL_PROGRAM;
	pargv[pargc] = NULL;

	return proot_main(pargc, pargv); /* remove_scratch() runs at exit, or the next input's sweep */
}
