# Linux Kernel Patch: Per-Process Resource Tracker

## Overview

This patch adds a **per-process resource tracking subsystem** to the Linux kernel. It enables monitoring and limiting of heap memory and open file usage by user-space processes. It introduces a new set of system calls, internal tracking infrastructure, and modifies relevant parts of the kernel to enforce quotas.

## Features

- **New System Calls:**
  - `sys_register(pid_t pid)` – Start tracking a process.
  - `sys_fetch(struct per_proc_resource *stats, pid_t pid)` – Retrieve tracked resource statistics.
  - `sys_deregister(pid_t pid)` – Stop tracking a process.
  - `sys_resource_cap(pid_t pid, long heap_quota, long file_quota)` – Set heap and file descriptor quotas.
  - `sys_resource_reset(pid_t pid)` – Reset resource usage statistics.

- **Tracked Metrics:**
  - `heapsize` – Total memory allocated via `brk` and `mmap`.
  - `openfile_count` – Count of open file descriptors.
  - `heapsize_quota` – Maximum allowed heap memory.
  - `openfile_quota` – Maximum number of allowed open files.

- **Kernel Modifications:**
  - `fs/open.c`: Hooks into `open` and `close` to track open files.
  - `mm/mmap.c`, `mm/nommu.c`: Hooks into memory management (`brk`, `mmap`, `munmap`) to track memory changes.
  - `kernel/fork.c`: Adds `yashscall` syscall for sanity testing.
  - `arch/x86/entry/syscalls/syscall_64.tbl`: Adds new syscall numbers.
  - `include/linux/restracker.h`: Declares tracking APIs and structs.
  - `kernel/restracker.c`: Implements tracking logic and internal functions.

## Kernel Patch Contents

- `restracker.c`: Implements resource tracking backend.
- `restracker.h`: Header file for internal tracking API.
- `syscall_64.tbl`: Registers syscall numbers 548–553.
- `syscalls.h`: Declares new syscalls.
- `mmap.c`, `nommu.c`, `open.c`: Hooks into `brk`, `mmap`, `munmap`, `open`, and `close`.

## Example usage

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/mman.h>

#define SYS_REG 549
#define SYS_QUERY 550
#define SYS_UNREG 551
#define SYS_RESOURCE_CAP 552
#define SYS_RESOURCE_RESET 553

struct per_proc_resource {
    pid_t pid;
    unsigned long heapsize;
    unsigned long openfile_count;
    unsigned long heapsize_quota;
    unsigned long openfile_quota;
};

#define _GNU_SOURCE

#define MB(x) ((x) * 1024 * 1024)

// Get Resident Set Size (RSS) from userspace
long get_rss_kb() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss; // RSS in KB
}

// Get page-aligned memory size
long get_page_aligned_bytes() {
    long pages = sysconf(_SC_PAGESIZE); // Page size in bytes
    long rss_kb = get_rss_kb();
    return (rss_kb * 1024 / pages) * pages; // Align to pages
}

// Fetch tracked heap size from kernel
unsigned long fetch_tracked_heap(pid_t pid) {
    struct per_proc_resource stats;
    if (syscall(SYS_QUERY, &stats, pid) == 0) {
        return stats.heapsize;
    } else {
        perror("sys_fetch syscall failed");
        return 0;
    }
}

long get_heap_size() {
    return (long)sbrk(0);  // Get current program break
}

// Function to query memory usage via `sysfect` syscall
long get_tracked_memory_syscall(pid_t pid) {
    struct per_proc_resource stats;
    long result = syscall(SYS_QUERY, &stats, pid);
    if (result == -1) {
        perror("sysfect syscall failed");
        return -1;
    }
    return stats.heapsize; // Return tracked heap size
}


int main() {
    pid_t pid = getpid();
    printf("Testing resource tracker for PID: %d\n", pid);
    size_t alloc_size = MB(20);

    // Register process
    if (syscall(SYS_REG, pid) < 0) {
        perror("syscall register failed");
        return 1;
    }
    printf("Process registered successfully.\n");

    // Set resource quotas (heap: 100 MB, file descriptors: 50)
    long heap_quota = 40; // 100 MB
    long file_quota = 1;
    if (syscall(SYS_RESOURCE_CAP, pid, heap_quota, file_quota) < 0) {
        perror("syscall resource_cap failed");
        return 1;
    }
    printf("Resource quotas set successfully (heap: %ld, files: %ld).\n", heap_quota, file_quota);

    int fds[4] = {-1, -1, -1, -1};
    char *files[] = {"/bin/dummy_1", "/bin/dummy_2"};

    void *mmap_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mmap_ptr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    for (int i = 0; i < 2; i++) {
        fds[i] = open(files[i], O_RDONLY);
        if (fds[i] == -1) perror("open failed");
    }

    // Fetch resource usage stats
    struct per_proc_resource stats;
    if (syscall(SYS_QUERY, &stats, pid) < 0) {
        perror("syscall fetch failed");
        return 1;
    }
    printf("Fetched stats: PID: %d, Heap: %ld, Files: %d, Heap Quota: %ld, File Quota: %d\n",
           stats.pid, stats.heapsize, stats.openfile_count, stats.heapsize_quota, stats.openfile_quota);

    for (int i = 0; i < 2; i++) {
        if (fds[i] != -1) close(fds[i]);
    }

    if (syscall(SYS_QUERY, &stats, pid) < 0) {
        perror("syscall fetch failed");
        return 1;
    }
    printf("Fetched stats: PID: %d, Heap: %ld, Files: %d, Heap Quota: %ld, File Quota: %d\n",
           stats.pid, stats.heapsize, stats.openfile_count, stats.heapsize_quota, stats.openfile_quota);

    munmap(mmap_ptr, alloc_size); // Free mmap region

    // Deregister process
    if (syscall(SYS_UNREG, pid) < 0) {
        perror("syscall deregister failed");
        return 1;
    }
    printf("Process deregistered successfully.\n");

    return 0;
}
```