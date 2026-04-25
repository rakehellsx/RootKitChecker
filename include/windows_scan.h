/**
 * windows_scan.h  –  Windows memory forensics detection module
 *
 * Covers:
 *  - Hidden / unlinked processes (PsList vs PsScan vs PsXView)
 *  - Inactive / terminated processes
 *  - Rootkit indicators: SSDT hooks, driver anomalies, hollow processes
 *  - Hidden network connections (NetScan vs NetStat)
 *  - Hidden kernel modules (Modules vs ModScan vs DriverScan)
 *  - Kernel data collection:
 *      os_info           windows.info.Info
 *      loaded_modules    windows.modules.Modules
 *      module_dumps      windows.modules.Modules --dump
 *      driver_irps       windows.driverirp.DriverIrp
 *      unloaded_modules  windows.unloadedmodules.UnloadedModules
 *      callbacks         windows.callbacks.Callbacks
 *      timers            windows.timers.Timers
 *      big_pools         windows.bigpools.BigPools
 *      memory_map        windows.memmap.Memmap
 *      statistics        windows.statistics.Statistics
 *      virtual_map       windows.virtmap.VirtMap
 */

#ifndef WINDOWS_SCAN_H
#define WINDOWS_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "memscope.h"

/* ------------------------------------------------------------------ */
/*  Detection functions                                                 */
/* ------------------------------------------------------------------ */

/** Collect basic Windows kernel information (windows.info). */
int windows_get_kernel_info(const char *image_path, KernelInfo *info);

/** Enumerate all processes using PsList (linked-list walk). */
int windows_get_pslist(const char *image_path,
                       ProcessRecord **out_procs, int *out_count);

/** Enumerate all processes using PsScan (pool tag scan). */
int windows_get_psscan(const char *image_path,
                       ProcessRecord **out_procs, int *out_count);

/** Run PsXView cross-view to detect hidden processes. */
int windows_get_psxview(const char *image_path,
                        ProcessRecord **out_procs, int *out_count);

/** Detect hidden and inactive processes (PsList vs PsScan). */
int windows_detect_hidden_processes(const char *image_path,
                                    ProcessRecord **out_hidden,
                                    int *out_hidden_count,
                                    ProcessRecord **out_inactive,
                                    int *out_inactive_count);

/** Enumerate network connections via NetScan (pool scan). */
int windows_get_netscan(const char *image_path,
                        NetRecord **out_nets, int *out_count);

/** Enumerate network connections via NetStat (active list). */
int windows_get_netstat(const char *image_path,
                        NetRecord **out_nets, int *out_count);

/** Detect hidden network connections (NetScan but not NetStat). */
int windows_detect_hidden_connections(const char *image_path,
                                      NetRecord **out_hidden,
                                      int *out_count);

/** Enumerate kernel modules via Modules plugin (linked list). */
int windows_get_modules(const char *image_path,
                        ModuleRecord **out_mods, int *out_count);

/** Enumerate kernel modules via ModScan (pool scan). */
int windows_get_modscan(const char *image_path,
                        ModuleRecord **out_mods, int *out_count);

/** Enumerate drivers via DriverScan. */
int windows_get_driverscan(const char *image_path,
                            ModuleRecord **out_mods, int *out_count);

/** Detect hidden kernel modules (ModScan but not Modules). */
int windows_detect_hidden_modules(const char *image_path,
                                  ModuleRecord **out_hidden,
                                  int *out_count);

/** Detect SSDT hooks. */
int windows_get_ssdt_hooks(const char *image_path,
                            HookRecord **out_hooks, int *out_count);

/** Detect hollow processes (process hollowing). */
int windows_detect_hollow_processes(const char *image_path,
                                    ProcessRecord **out_procs,
                                    int *out_count);

/** Detect driver module anomalies (DriverModule plugin). */
int windows_detect_driver_anomalies(const char *image_path,
                                    ModuleRecord **out_mods, int *out_count);

/* ------------------------------------------------------------------ */
/*  Kernel data collection functions                                    */
/* ------------------------------------------------------------------ */

/**
 * windows.info.Info
 * Collect OS version, kernel base address, KDBG structure details.
 * Results stored in WinKernelData.os_info[].
 */
int windows_collect_os_info(const char *image_path,
                             WinKernelData *kd);

/**
 * windows.modules.Modules
 * Full loaded driver/module list (PsLoadedModuleList walk):
 * ntoskrnl.exe, drivers, HAL, etc.
 * Results stored in WinKernelData.loaded_modules[].
 */
int windows_collect_loaded_modules(const char *image_path,
                                    WinKernelData *kd);

/**
 * windows.modules.Modules --dump
 * Extract kernel driver .sys files to disk for static analysis.
 * Results stored in WinKernelData.module_dumps[].
 * Dumped files are written to <dump_dir>/ (default: ./module_dumps/).
 */
int windows_collect_module_dumps(const char *image_path,
                                  WinKernelData *kd,
                                  const char *dump_dir);

/**
 * windows.driverirp.DriverIrp
 * Parse DRIVER_OBJECT->MajorFunction array for each driver.
 * Detects IRP hooks where a handler points outside the driver's own range.
 * Results stored in WinKernelData.driver_irps[].
 */
int windows_collect_driver_irps(const char *image_path,
                                  WinKernelData *kd);

/**
 * windows.unloadedmodules.UnloadedModules
 * Extract PsUnloadedDriversList to discover drivers that were loaded
 * and subsequently unloaded (common pattern for dropper/loader rootkits).
 * Results stored in WinKernelData.unloaded_modules[].
 */
int windows_collect_unloaded_modules(const char *image_path,
                                      WinKernelData *kd);

/**
 * windows.callbacks.Callbacks
 * Enumerate kernel notification callbacks:
 *   PsSetCreateProcessNotifyRoutine   (CreateProcessNotifyRoutine)
 *   PsSetCreateThreadNotifyRoutine    (CreateThreadNotifyRoutine)
 *   PsSetLoadImageNotifyRoutine       (LoadImageNotifyRoutine)
 *   CmRegisterCallback                (RegistryCallback)
 *   IoRegisterFsRegistrationChange    (FsChangeNotify)
 *   DbgkRegisterPluginCallbacks       (DbgkPluginCallbacks)
 * Results stored in WinKernelData.callbacks[].
 */
int windows_collect_callbacks(const char *image_path,
                               WinKernelData *kd);

/**
 * windows.timers.Timers
 * Parse KTIMER objects from the kernel timer list.
 * Rootkits often install periodic DPC timers to re-hook or maintain
 * persistence after detection/removal.
 * Results stored in WinKernelData.timers[].
 */
int windows_collect_timers(const char *image_path,
                            WinKernelData *kd);

/**
 * windows.bigpools.BigPools
 * Large kernel pool allocations (rootkits often allocate big pools
 * to hide shellcode or data structures).
 * Results stored in WinKernelData.big_pools[].
 */
int windows_collect_big_pools(const char *image_path,
                               WinKernelData *kd);

/**
 * windows.memmap.Memmap
 * Kernel virtual address space mapping.
 * Results stored in WinKernelData.memory_map[].
 */
int windows_collect_memory_map(const char *image_path,
                                WinKernelData *kd);

/**
 * windows.statistics.Statistics
 * Memory usage statistics summary.
 * Results stored in WinKernelData.statistics[].
 */
int windows_collect_statistics(const char *image_path,
                                WinKernelData *kd);

/**
 * windows.virtmap.VirtMap
 * Virtual memory region layout.
 * Results stored in WinKernelData.virtual_map[].
 */
int windows_collect_virtual_map(const char *image_path,
                                 WinKernelData *kd);

/**
 * Collect all Windows kernel data into WinKernelData.
 * Calls all collection functions above.
 *
 * @param dump_dir  Directory to write extracted .sys files.
 *                  Pass NULL to use the value of MEMSCOPE_DUMP_DIR env var,
 *                  or "./module_dumps" as the final fallback.
 */
int windows_collect_kernel_data(const char *image_path,
                                 WinKernelData *kd,
                                 const char *dump_dir);

/**
 * Run the full Windows scan and populate a ScanResult.
 * Includes both detection and kernel data collection.
 */
int windows_full_scan(const char *image_path, ScanResult *result);

#ifdef __cplusplus
}
#endif

#endif /* WINDOWS_SCAN_H */
