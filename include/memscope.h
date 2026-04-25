/**
 * memscope.h - Memory Forensics Tool based on Volatility3
 *
 * Main header: data structures, constants, and function declarations
 * for Windows/Linux hidden process, rootkit, network detection,
 * and comprehensive kernel data collection.
 */

#ifndef MEMSCOPE_H
#define MEMSCOPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "../../third_party/cjson/cJSON.h"

/* ------------------------------------------------------------------ */
/*  Version                                                             */
/* ------------------------------------------------------------------ */
#define MEMSCOPE_VERSION_MAJOR 1
#define MEMSCOPE_VERSION_MINOR 1
#define MEMSCOPE_VERSION_PATCH 0
#define MEMSCOPE_VERSION_STR   "1.1.0"

/* ------------------------------------------------------------------ */
/*  OS type detected from the image                                    */
/* ------------------------------------------------------------------ */
typedef enum {
    OS_UNKNOWN  = 0,
    OS_WINDOWS  = 1,
    OS_LINUX    = 2,
    OS_MACOS    = 3
} OsType;

/* ------------------------------------------------------------------ */
/*  Process record                                                      */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t    pid;
    uint64_t    ppid;
    char        name[256];
    char        cmdline[1024];
    char        create_time[64];
    char        exit_time[64];
    uint64_t    offset;          /* virtual address / task_struct addr */
    bool        in_pslist;       /* found via linked-list walk         */
    bool        in_psscan;       /* found via pool/heap scan           */
    bool        in_pidhashtable; /* Linux: found in PID hash table     */
    bool        hidden;          /* determined to be hidden            */
    bool        inactive;        /* process has exited                 */
    char        source[64];      /* detection source tag               */
} ProcessRecord;

/* ------------------------------------------------------------------ */
/*  Network connection record                                           */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t    pid;
    char        proc_name[256];
    char        local_addr[64];
    int         local_port;
    char        remote_addr[64];
    int         remote_port;
    char        proto[16];       /* TCP / UDP / TCP6 / UDP6            */
    char        state[32];
    uint64_t    offset;
    bool        hidden;          /* not visible in normal netstat      */
} NetRecord;

/* ------------------------------------------------------------------ */
/*  Kernel module / driver record                                       */
/* ------------------------------------------------------------------ */
typedef struct {
    char        name[256];
    uint64_t    base;
    uint64_t    size;
    char        path[512];
    bool        hidden;          /* not in normal module list          */
    char        source[64];      /* lsmod / modscan / driverscan …    */
} ModuleRecord;

/* ------------------------------------------------------------------ */
/*  Syscall / IDT / hook record                                         */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t    index;
    char        symbol[256];
    uint64_t    handler_addr;
    char        module[256];
    bool        hooked;
    char        hook_type[64];   /* SSDT / IDT / afinfo / eBPF / …    */
} HookRecord;

/* ------------------------------------------------------------------ */
/*  Generic key-value record (for pool entries, iomem, vmcoreinfo …)  */
/* ------------------------------------------------------------------ */
typedef struct {
    char        key[256];
    char        value[512];
    char        extra[256];      /* optional third column              */
} KVRecord;

/* ------------------------------------------------------------------ */
/*  Memory region record (memmap / virtmap / iomem)                    */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t    start;
    uint64_t    end;
    uint64_t    size;
    char        name[256];       /* region / segment name              */
    char        flags[64];       /* permissions / type flags           */
    uint64_t    pid;             /* owning process (0 = kernel)        */
} MemRegionRecord;

/* ------------------------------------------------------------------ */
/*  Big pool allocation record (Windows BigPools)                      */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t    virtual_addr;
    uint64_t    size;
    char        tag[8];          /* 4-byte pool tag + NUL              */
    char        type[32];        /* NonPagedPool / PagedPool / …       */
    bool        suspicious;      /* tag not in known-good list         */
} BigPoolRecord;

/* ------------------------------------------------------------------ */
/*  Kernel thread record (Linux kthreads)                              */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t    pid;
    uint64_t    ppid;
    char        name[256];
    uint64_t    offset;
    char        state[32];
} KThreadRecord;

/* ------------------------------------------------------------------ */
/*  Mount info record (Linux mountinfo)                                */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t    pid;             /* namespace pid                      */
    char        devname[256];
    char        path[512];
    char        fstype[64];
    char        options[256];
} MountRecord;

/* ------------------------------------------------------------------ */
/*  Kernel information (basic OS/image metadata)                       */
/* ------------------------------------------------------------------ */
typedef struct {
    char        os_type[32];
    char        os_version[256];
    char        kernel_version[256];
    char        architecture[32];
    uint64_t    kdbg_offset;
    uint64_t    dtb;
    char        build_str[256];
    char        image_type[64];
} KernelInfo;

/* ------------------------------------------------------------------ */
/*  Driver IRP dispatch routine record (windows.driverirp.DriverIrp)   */
/* ------------------------------------------------------------------ */
typedef struct {
    char        driver_name[256];   /* e.g. \Driver\Null                */
    char        driver_path[512];   /* full image path of the driver    */
    uint32_t    irp_index;          /* MajorFunction index (0-27)       */
    char        irp_name[64];       /* IRP_MJ_CREATE, IRP_MJ_READ …    */
    uint64_t    handler_addr;       /* virtual address of the handler   */
    char        handler_module[256];/* module owning the handler        */
    bool        hooked;             /* handler outside driver's range   */
} IrpRecord;

/* ------------------------------------------------------------------ */
/*  Unloaded module record (windows.unloadedmodules.UnloadedModules)   */
/* ------------------------------------------------------------------ */
typedef struct {
    char        name[256];          /* driver base name                 */
    uint64_t    start_addr;         /* load base address                */
    uint64_t    end_addr;           /* load end address                 */
    char        unload_time[64];    /* timestamp when driver unloaded   */
} UnloadedModuleRecord;

/* ------------------------------------------------------------------ */
/*  Kernel callback record (windows.callbacks.Callbacks)               */
/* ------------------------------------------------------------------ */
typedef struct {
    char        callback_type[128]; /* CreateProcess / LoadImage / …   */
    uint64_t    callback_addr;      /* address of the callback routine  */
    char        module[256];        /* module owning the callback       */
    char        symbol[256];        /* resolved symbol name if any      */
    char        detail[512];        /* extra info (registry path, …)   */
} CallbackRecord;

/* ------------------------------------------------------------------ */
/*  Kernel timer record (windows.timers.Timers)                        */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t    offset;             /* KTIMER object address            */
    uint64_t    due_time;           /* absolute due time (100ns units)  */
    uint64_t    period;             /* period in ms (0 = one-shot)      */
    uint64_t    signaled;           /* 1 if timer is in signaled state  */
    uint64_t    routine_addr;       /* DPC routine address              */
    char        routine_module[256];/* module owning the DPC routine    */
    char        routine_symbol[256];/* resolved symbol name if any      */
} TimerRecord;

/* ------------------------------------------------------------------ */
/*  Module dump record (windows.modules.Modules --dump)                */
/* ------------------------------------------------------------------ */
typedef struct {
    char        name[256];          /* driver base name                 */
    uint64_t    base;               /* load base address                */
    uint64_t    size;               /* image size in bytes              */
    char        path[512];          /* original path in image           */
    char        dump_path[512];     /* local path where file was dumped */
    bool        dump_ok;            /* true if dump succeeded           */
} ModuleDumpRecord;

/* ------------------------------------------------------------------ */
/*  Windows kernel data collection                                      */
/* ------------------------------------------------------------------ */
typedef struct {
    /* windows.info.Info */
    KVRecord           *os_info;
    int                 os_info_count;

    /* windows.modules.Modules — full loaded driver list */
    ModuleRecord       *loaded_modules;
    int                 loaded_module_count;

    /* windows.modules.Modules --dump — extracted driver binaries */
    ModuleDumpRecord   *module_dumps;
    int                 module_dump_count;

    /* windows.driverirp.DriverIrp — IRP dispatch routine table */
    IrpRecord          *driver_irps;
    int                 driver_irp_count;

    /* windows.unloadedmodules.UnloadedModules — previously unloaded drivers */
    UnloadedModuleRecord *unloaded_modules;
    int                   unloaded_module_count;

    /* windows.callbacks.Callbacks — kernel notification callbacks */
    CallbackRecord     *callbacks;
    int                 callback_count;

    /* windows.timers.Timers — KTIMER objects */
    TimerRecord        *timers;
    int                 timer_count;

    /* windows.bigpools.BigPools — large kernel pool allocations */
    BigPoolRecord      *big_pools;
    int                 big_pool_count;

    /* windows.memmap.Memmap — kernel virtual address map */
    MemRegionRecord    *memory_map;
    int                 memory_map_count;

    /* windows.statistics.Statistics — memory statistics */
    KVRecord           *statistics;
    int                 statistics_count;

    /* windows.virtmap.VirtMap — virtual memory region layout */
    MemRegionRecord    *virtual_map;
    int                 virtual_map_count;
} WinKernelData;

/* ------------------------------------------------------------------ */
/*  Linux kernel data collection                                        */
/* ------------------------------------------------------------------ */
typedef struct {
    /* linux.kallsyms.Kallsyms — kernel symbol table */
    KVRecord       *kallsyms;
    int             kallsyms_count;

    /* linux.iomem.IOMem — physical memory / I/O resource map */
    MemRegionRecord *iomem;
    int              iomem_count;

    /* linux.vmcoreinfo.VMCoreInfo — vmcore metadata */
    KVRecord       *vmcoreinfo;
    int             vmcoreinfo_count;

    /* linux.kmsg.Kmsg — kernel ring buffer messages */
    KVRecord       *kernel_messages;
    int             kernel_message_count;

    /* linux.boottime.Boottime — system boot timestamp */
    char            boot_time[128];

    /* linux.lsmod.Lsmod — loaded kernel modules */
    ModuleRecord   *loaded_modules;
    int             loaded_module_count;

    /* linux.kthreads.Kthreads — kernel threads */
    KThreadRecord  *kernel_threads;
    int             kernel_thread_count;

    /* linux.ebpf.EBPF — eBPF programs */
    HookRecord     *ebpf_programs;
    int             ebpf_program_count;

    /* linux.netfilter.Netfilter — netfilter hook chain */
    HookRecord     *netfilter_hooks;
    int             netfilter_hook_count;

    /* linux.mountinfo.MountInfo — filesystem mount points */
    MountRecord    *mount_info;
    int             mount_info_count;
} LinuxKernelData;

/* ------------------------------------------------------------------ */
/*  Full scan result container                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    KernelInfo      kernel;

    /* ---- process detection ---- */
    ProcessRecord  *processes;
    int             process_count;

    ProcessRecord  *hidden_processes;
    int             hidden_process_count;

    ProcessRecord  *inactive_processes;
    int             inactive_process_count;

    /* ---- network detection ---- */
    NetRecord      *connections;
    int             connection_count;

    NetRecord      *hidden_connections;
    int             hidden_connection_count;

    /* ---- module detection ---- */
    ModuleRecord   *modules;
    int             module_count;

    ModuleRecord   *hidden_modules;
    int             hidden_module_count;

    /* ---- hook / rootkit detection ---- */
    HookRecord     *hooks;
    int             hook_count;

    /* ---- kernel data (OS-specific) ---- */
    WinKernelData   win_kernel;   /* populated for Windows images */
    LinuxKernelData lnx_kernel;   /* populated for Linux images   */

    /* ---- metadata ---- */
    char            scan_time[64];
    char            image_path[1024];
    int             error_count;
    char          **errors;
} ScanResult;

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * Initialize the Python interpreter and volatility3 environment.
 * Must be called once before any scan functions.
 * @param venv_path  Path to the Python virtual-environment directory,
 *                   or NULL to use the system Python.
 * @return 0 on success, negative on error.
 */
int memscope_init(const char *venv_path);

/**
 * Detect the OS type of the memory image.
 */
OsType memscope_detect_os(const char *image_path);

/**
 * Run a full forensic scan on the given memory image.
 * Fills in *result; caller must free with memscope_free_result().
 * @return 0 on success, negative on error.
 */
int memscope_scan(const char *image_path, ScanResult *result);

/**
 * Free all memory owned by a ScanResult.
 */
void memscope_free_result(ScanResult *result);

/**
 * Serialize a ScanResult to a cJSON object.
 * Caller is responsible for calling cJSON_Delete() on the returned object.
 */
cJSON *memscope_to_json(const ScanResult *result);

/**
 * Finalize the Python interpreter. Call once at program exit.
 */
void memscope_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMSCOPE_H */
