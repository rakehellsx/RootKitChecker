/**
 * memscope.h - Memory Forensics Tool based on Volatility3
 *
 * Main header: data structures, constants, and function declarations
 * for Windows/Linux hidden process, rootkit, and network detection.
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
#define MEMSCOPE_VERSION_MINOR 0
#define MEMSCOPE_VERSION_PATCH 0
#define MEMSCOPE_VERSION_STR   "1.0.0"

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
/*  Syscall / IDT hook record                                           */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t    index;
    char        symbol[256];
    uint64_t    handler_addr;
    char        module[256];
    bool        hooked;
    char        hook_type[64];   /* SSDT / IDT / inline / …           */
} HookRecord;

/* ------------------------------------------------------------------ */
/*  Kernel information                                                  */
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
/*  Full scan result container                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    KernelInfo      kernel;

    ProcessRecord  *processes;
    int             process_count;

    ProcessRecord  *hidden_processes;
    int             hidden_process_count;

    ProcessRecord  *inactive_processes;
    int             inactive_process_count;

    NetRecord      *connections;
    int             connection_count;

    NetRecord      *hidden_connections;
    int             hidden_connection_count;

    ModuleRecord   *modules;
    int             module_count;

    ModuleRecord   *hidden_modules;
    int             hidden_module_count;

    HookRecord     *hooks;
    int             hook_count;

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
