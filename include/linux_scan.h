/**
 * linux_scan.h  –  Linux memory forensics detection module
 *
 * Covers:
 *  - Hidden / unlinked processes (PsList vs PsScan vs PIDHashTable)
 *  - Inactive / zombie processes
 *  - Rootkit indicators: hidden modules, syscall hooks, IDT hooks,
 *    afinfo tampering, credential anomalies, eBPF, netfilter hooks,
 *    TTY check, keyboard notifiers
 *  - Hidden network connections (Sockstat)
 *  - Kernel information (VMCoreInfo / Kallsyms)
 */

#ifndef LINUX_SCAN_H
#define LINUX_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "memscope.h"

/**
 * Collect Linux kernel information from vmcoreinfo / kallsyms.
 */
int linux_get_kernel_info(const char *image_path, KernelInfo *info);

/**
 * Enumerate processes via PsList (task_struct linked list).
 */
int linux_get_pslist(const char *image_path,
                     ProcessRecord **out_procs, int *out_count);

/**
 * Enumerate processes via PsScan (brute-force memory scan).
 */
int linux_get_psscan(const char *image_path,
                     ProcessRecord **out_procs, int *out_count);

/**
 * Enumerate processes via PID hash table walk.
 */
int linux_get_pidhashtable(const char *image_path,
                           ProcessRecord **out_procs, int *out_count);

/**
 * Detect hidden processes by cross-referencing pslist / psscan /
 * pidhashtable.  Processes in psscan/pidhashtable but not pslist
 * are flagged as hidden.
 */
int linux_detect_hidden_processes(const char *image_path,
                                  ProcessRecord **out_hidden,
                                  int *out_hidden_count,
                                  ProcessRecord **out_inactive,
                                  int *out_inactive_count);

/**
 * Enumerate network sockets via Sockstat.
 */
int linux_get_sockstat(const char *image_path,
                       NetRecord **out_nets, int *out_count);

/**
 * Detect hidden network connections.
 * Compares sockstat results against process file descriptors (lsof).
 */
int linux_detect_hidden_connections(const char *image_path,
                                    NetRecord **out_hidden, int *out_count);

/**
 * Enumerate loaded kernel modules via Lsmod (linked list).
 */
int linux_get_lsmod(const char *image_path,
                    ModuleRecord **out_mods, int *out_count);

/**
 * Detect hidden kernel modules (Check_modules / Hidden_modules plugin).
 */
int linux_detect_hidden_modules(const char *image_path,
                                ModuleRecord **out_hidden, int *out_count);

/**
 * Detect syscall table hooks (Check_syscall plugin).
 */
int linux_get_syscall_hooks(const char *image_path,
                             HookRecord **out_hooks, int *out_count);

/**
 * Detect IDT hooks (Check_idt plugin).
 */
int linux_get_idt_hooks(const char *image_path,
                         HookRecord **out_hooks, int *out_count);

/**
 * Detect afinfo structure tampering (Check_afinfo plugin).
 * Used by rootkits to hide network connections.
 */
int linux_check_afinfo(const char *image_path,
                        HookRecord **out_hooks, int *out_count);

/**
 * Detect credential anomalies (Check_creds plugin).
 */
int linux_check_creds(const char *image_path,
                       ProcessRecord **out_procs, int *out_count);

/**
 * Detect suspicious eBPF programs (EBPF plugin).
 */
int linux_check_ebpf(const char *image_path,
                      HookRecord **out_hooks, int *out_count);

/**
 * Detect netfilter hooks (Netfilter plugin).
 */
int linux_check_netfilter(const char *image_path,
                           HookRecord **out_hooks, int *out_count);

/**
 * Detect TTY handler modifications (tty_check plugin).
 */
int linux_check_tty(const char *image_path,
                     HookRecord **out_hooks, int *out_count);

/**
 * Detect keyboard notifier hooks (keyboard_notifiers plugin).
 */
int linux_check_keyboard_notifiers(const char *image_path,
                                    HookRecord **out_hooks, int *out_count);

/**
 * Run the full Linux scan and populate a ScanResult.
 */
int linux_full_scan(const char *image_path, ScanResult *result);

#ifdef __cplusplus
}
#endif

#endif /* LINUX_SCAN_H */
