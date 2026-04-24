/**
 * windows_scan.h  –  Windows memory forensics detection module
 *
 * Covers:
 *  - Hidden / unlinked processes (PsList vs PsScan vs PsXView)
 *  - Inactive / terminated processes
 *  - Rootkit indicators: SSDT hooks, driver anomalies, hollow processes
 *  - Hidden network connections (NetScan vs NetStat)
 *  - Kernel information (windows.info)
 *  - Hidden kernel modules (Modules vs ModScan vs DriverScan)
 */

#ifndef WINDOWS_SCAN_H
#define WINDOWS_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "memscope.h"

/**
 * Collect Windows kernel information from windows.info plugin.
 */
int windows_get_kernel_info(const char *image_path, KernelInfo *info);

/**
 * Enumerate all processes using PsList (linked-list walk).
 * Caller must free *out_procs with free().
 */
int windows_get_pslist(const char *image_path,
                       ProcessRecord **out_procs, int *out_count);

/**
 * Enumerate all processes using PsScan (pool tag scan).
 * Includes terminated / inactive processes.
 */
int windows_get_psscan(const char *image_path,
                       ProcessRecord **out_procs, int *out_count);

/**
 * Run PsXView cross-view comparison to detect hidden processes.
 * Merges results from pslist, psscan, thrdproc, pspcid, csrss, session,
 * deskthrd and marks discrepancies as hidden.
 */
int windows_get_psxview(const char *image_path,
                        ProcessRecord **out_procs, int *out_count);

/**
 * Detect hidden processes by comparing PsList vs PsScan.
 * Processes found in PsScan but not PsList are flagged hidden.
 * Processes with exit_time set are flagged inactive.
 */
int windows_detect_hidden_processes(const char *image_path,
                                    ProcessRecord **out_hidden,
                                    int *out_hidden_count,
                                    ProcessRecord **out_inactive,
                                    int *out_inactive_count);

/**
 * Enumerate network connections via NetScan (pool scan).
 */
int windows_get_netscan(const char *image_path,
                        NetRecord **out_nets, int *out_count);

/**
 * Enumerate network connections via NetStat (active connections).
 */
int windows_get_netstat(const char *image_path,
                        NetRecord **out_nets, int *out_count);

/**
 * Detect hidden network connections (in NetScan but not NetStat).
 */
int windows_detect_hidden_connections(const char *image_path,
                                      NetRecord **out_hidden,
                                      int *out_count);

/**
 * Enumerate kernel modules via Modules plugin (linked list).
 */
int windows_get_modules(const char *image_path,
                        ModuleRecord **out_mods, int *out_count);

/**
 * Enumerate kernel modules via ModScan (pool scan).
 */
int windows_get_modscan(const char *image_path,
                        ModuleRecord **out_mods, int *out_count);

/**
 * Enumerate drivers via DriverScan.
 */
int windows_get_driverscan(const char *image_path,
                            ModuleRecord **out_mods, int *out_count);

/**
 * Detect hidden kernel modules (in ModScan but not Modules).
 */
int windows_detect_hidden_modules(const char *image_path,
                                  ModuleRecord **out_hidden,
                                  int *out_count);

/**
 * Detect SSDT hooks.
 */
int windows_get_ssdt_hooks(const char *image_path,
                            HookRecord **out_hooks, int *out_count);

/**
 * Detect hollow processes (process hollowing).
 */
int windows_detect_hollow_processes(const char *image_path,
                                    ProcessRecord **out_procs,
                                    int *out_count);

/**
 * Detect driver module anomalies (DriverModule plugin).
 */
int windows_detect_driver_anomalies(const char *image_path,
                                    ModuleRecord **out_mods, int *out_count);

/**
 * Run the full Windows scan and populate a ScanResult.
 */
int windows_full_scan(const char *image_path, ScanResult *result);

#ifdef __cplusplus
}
#endif

#endif /* WINDOWS_SCAN_H */
