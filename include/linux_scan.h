/**
 * linux_scan.h  –  Linux memory forensics detection module
 *
 * Covers:
 *  - Hidden / unlinked processes (PsList vs PsScan vs PIDHashTable)
 *  - Inactive / zombie processes
 *  - Rootkit indicators: hidden modules, syscall hooks, IDT hooks,
 *    afinfo tampering, credential anomalies, eBPF, netfilter hooks,
 *    TTY check, keyboard notifiers
 *  - Hidden network connections (Sockstat vs Lsof)
 *  - Kernel data collection:
 *      kallsyms         linux.kallsyms.Kallsyms
 *      iomem            linux.iomem.IOMem
 *      vmcoreinfo       linux.vmcoreinfo.VMCoreInfo
 *      kernel_messages  linux.kmsg.Kmsg
 *      boot_time        linux.boottime.Boottime
 *      loaded_modules   linux.lsmod.Lsmod
 *      kernel_threads   linux.kthreads.Kthreads
 *      ebpf_programs    linux.ebpf.EBPF
 *      netfilter_hooks  linux.netfilter.Netfilter
 *      mount_info       linux.mountinfo.MountInfo
 */

#ifndef LINUX_SCAN_H
#define LINUX_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "memscope.h"

/* ------------------------------------------------------------------ */
/*  Detection functions                                                 */
/* ------------------------------------------------------------------ */
int linux_get_kernel_info(const char *image_path, KernelInfo *info);
int linux_get_pslist(const char *image_path, ProcessRecord **out_procs, int *out_count);
int linux_get_psscan(const char *image_path, ProcessRecord **out_procs, int *out_count);
int linux_get_pidhashtable(const char *image_path, ProcessRecord **out_procs, int *out_count);
int linux_detect_hidden_processes(const char *image_path,
                                  ProcessRecord **out_hidden, int *out_hidden_count,
                                  ProcessRecord **out_inactive, int *out_inactive_count);
int linux_get_sockstat(const char *image_path, NetRecord **out_nets, int *out_count);
int linux_detect_hidden_connections(const char *image_path, NetRecord **out_hidden, int *out_count);
int linux_get_lsmod(const char *image_path, ModuleRecord **out_mods, int *out_count);
int linux_detect_hidden_modules(const char *image_path, ModuleRecord **out_hidden, int *out_count);
int linux_get_syscall_hooks(const char *image_path, HookRecord **out_hooks, int *out_count);
int linux_get_idt_hooks(const char *image_path, HookRecord **out_hooks, int *out_count);
int linux_check_afinfo(const char *image_path, HookRecord **out_hooks, int *out_count);
int linux_check_creds(const char *image_path, ProcessRecord **out_procs, int *out_count);
int linux_check_ebpf(const char *image_path, HookRecord **out_hooks, int *out_count);
int linux_check_netfilter(const char *image_path, HookRecord **out_hooks, int *out_count);
int linux_check_tty(const char *image_path, HookRecord **out_hooks, int *out_count);
int linux_check_keyboard_notifiers(const char *image_path, HookRecord **out_hooks, int *out_count);

/* ------------------------------------------------------------------ */
/*  Kernel data collection functions                                    */
/* ------------------------------------------------------------------ */

/** linux.kallsyms.Kallsyms — kernel symbol table */
int linux_collect_kallsyms(const char *image_path, LinuxKernelData *kd);

/** linux.iomem.IOMem — physical memory / I/O resource map */
int linux_collect_iomem(const char *image_path, LinuxKernelData *kd);

/** linux.vmcoreinfo.VMCoreInfo — vmcore metadata */
int linux_collect_vmcoreinfo(const char *image_path, LinuxKernelData *kd);

/** linux.kmsg.Kmsg — kernel ring buffer (dmesg) */
int linux_collect_kernel_messages(const char *image_path, LinuxKernelData *kd);

/** linux.boottime.Boottime — system boot timestamp */
int linux_collect_boot_time(const char *image_path, LinuxKernelData *kd);

/** linux.lsmod.Lsmod — loaded kernel modules (full detail) */
int linux_collect_loaded_modules(const char *image_path, LinuxKernelData *kd);

/** linux.kthreads.Kthreads — kernel thread enumeration */
int linux_collect_kernel_threads(const char *image_path, LinuxKernelData *kd);

/** linux.ebpf.EBPF — eBPF programs and attachment points */
int linux_collect_ebpf_programs(const char *image_path, LinuxKernelData *kd);

/** linux.netfilter.Netfilter — netfilter hook chain */
int linux_collect_netfilter_hooks(const char *image_path, LinuxKernelData *kd);

/** linux.mountinfo.MountInfo — filesystem mount points */
int linux_collect_mount_info(const char *image_path, LinuxKernelData *kd);

/** Collect all Linux kernel data (calls all 10 functions above) */
int linux_collect_kernel_data(const char *image_path, LinuxKernelData *kd);

/** Run the full Linux scan and populate a ScanResult. */
int linux_full_scan(const char *image_path, ScanResult *result);

#ifdef __cplusplus
}
#endif

#endif /* LINUX_SCAN_H */
