/**
 * json_output.c  –  Serialize ScanResult to cJSON
 *
 * Covers all data structures including:
 *   - KernelInfo, ProcessRecord, NetRecord, ModuleRecord, HookRecord
 *   - KVRecord, MemRegionRecord, BigPoolRecord, KThreadRecord, MountRecord
 *   - WinKernelData (6 items), LinuxKernelData (10 items)
 */

#include "memscope.h"
#include "../../third_party/cjson/cJSON.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */
static void json_add_str(cJSON *obj, const char *key, const char *val)
{
    if (!val || strlen(val) == 0 || strcmp(val, "N/A") == 0)
        cJSON_AddNullToObject(obj, key);
    else
        cJSON_AddStringToObject(obj, key, val);
}

static void json_add_u64(cJSON *obj, const char *key, uint64_t val)
{
    char buf[32];
    if (val == 0) {
        cJSON_AddNullToObject(obj, key);
    } else {
        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
        cJSON_AddStringToObject(obj, key, buf);
    }
}

/* ------------------------------------------------------------------ */
/*  KernelInfo                                                          */
/* ------------------------------------------------------------------ */
static cJSON *kernel_info_to_json(const KernelInfo *k)
{
    cJSON *obj = cJSON_CreateObject();
    json_add_str(obj, "os_type",        k->os_type);
    json_add_str(obj, "os_version",     k->os_version);
    json_add_str(obj, "kernel_version", k->kernel_version);
    json_add_str(obj, "architecture",   k->architecture);
    json_add_str(obj, "build_str",      k->build_str);
    json_add_str(obj, "image_type",     k->image_type);
    json_add_u64(obj, "kdbg_offset",    k->kdbg_offset);
    json_add_u64(obj, "dtb",            k->dtb);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  ProcessRecord                                                       */
/* ------------------------------------------------------------------ */
static cJSON *process_to_json(const ProcessRecord *p)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "pid",  (double)p->pid);
    cJSON_AddNumberToObject(obj, "ppid", (double)p->ppid);
    json_add_str(obj, "name",        p->name);
    json_add_str(obj, "cmdline",     p->cmdline);
    json_add_str(obj, "create_time", p->create_time);
    json_add_str(obj, "exit_time",   p->exit_time);
    json_add_u64(obj, "offset",      p->offset);
    cJSON_AddBoolToObject(obj, "in_pslist",       p->in_pslist);
    cJSON_AddBoolToObject(obj, "in_psscan",       p->in_psscan);
    cJSON_AddBoolToObject(obj, "in_pidhashtable", p->in_pidhashtable);
    cJSON_AddBoolToObject(obj, "hidden",          p->hidden);
    cJSON_AddBoolToObject(obj, "inactive",        p->inactive);
    json_add_str(obj, "source", p->source);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  NetRecord                                                           */
/* ------------------------------------------------------------------ */
static cJSON *net_to_json(const NetRecord *n)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "pid", (double)n->pid);
    json_add_str(obj, "process",     n->proc_name);
    json_add_str(obj, "local_addr",  n->local_addr);
    cJSON_AddNumberToObject(obj, "local_port",  n->local_port);
    json_add_str(obj, "remote_addr", n->remote_addr);
    cJSON_AddNumberToObject(obj, "remote_port", n->remote_port);
    json_add_str(obj, "proto",  n->proto);
    json_add_str(obj, "state",  n->state);
    json_add_u64(obj, "offset", n->offset);
    cJSON_AddBoolToObject(obj, "hidden", n->hidden);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  ModuleRecord                                                        */
/* ------------------------------------------------------------------ */
static cJSON *module_to_json(const ModuleRecord *m)
{
    cJSON *obj = cJSON_CreateObject();
    json_add_str(obj, "name", m->name);
    json_add_u64(obj, "base", m->base);
    cJSON_AddNumberToObject(obj, "size", (double)m->size);
    json_add_str(obj, "path",   m->path);
    json_add_str(obj, "source", m->source);
    cJSON_AddBoolToObject(obj, "hidden", m->hidden);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  HookRecord                                                          */
/* ------------------------------------------------------------------ */
static cJSON *hook_to_json(const HookRecord *h)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "index", (double)h->index);
    json_add_str(obj, "symbol",    h->symbol);
    json_add_u64(obj, "handler",   h->handler_addr);
    json_add_str(obj, "module",    h->module);
    json_add_str(obj, "hook_type", h->hook_type);
    cJSON_AddBoolToObject(obj, "hooked", h->hooked);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  KVRecord                                                            */
/* ------------------------------------------------------------------ */
static cJSON *kv_to_json(const KVRecord *kv)
{
    cJSON *obj = cJSON_CreateObject();
    json_add_str(obj, "key",   kv->key);
    json_add_str(obj, "value", kv->value);
    if (kv->extra[0] != '\0' && strcmp(kv->extra, "N/A") != 0)
        json_add_str(obj, "extra", kv->extra);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  MemRegionRecord                                                     */
/* ------------------------------------------------------------------ */
static cJSON *memregion_to_json(const MemRegionRecord *r)
{
    cJSON *obj = cJSON_CreateObject();
    json_add_u64(obj, "start", r->start);
    json_add_u64(obj, "end",   r->end);
    cJSON_AddNumberToObject(obj, "size", (double)r->size);
    json_add_str(obj, "name",  r->name);
    if (r->flags[0] != '\0')
        json_add_str(obj, "flags", r->flags);
    if (r->pid != 0)
        cJSON_AddNumberToObject(obj, "pid", (double)r->pid);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  BigPoolRecord                                                       */
/* ------------------------------------------------------------------ */
static cJSON *bigpool_to_json(const BigPoolRecord *p)
{
    cJSON *obj = cJSON_CreateObject();
    json_add_u64(obj, "virtual_addr", p->virtual_addr);
    cJSON_AddNumberToObject(obj, "size", (double)p->size);
    json_add_str(obj, "tag",  p->tag);
    json_add_str(obj, "type", p->type);
    cJSON_AddBoolToObject(obj, "suspicious", p->suspicious);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  KThreadRecord                                                       */
/* ------------------------------------------------------------------ */
static cJSON *kthread_to_json(const KThreadRecord *t)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "pid",  (double)t->pid);
    cJSON_AddNumberToObject(obj, "ppid", (double)t->ppid);
    json_add_str(obj, "name",  t->name);
    json_add_u64(obj, "offset", t->offset);
    json_add_str(obj, "state", t->state);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  MountRecord                                                         */
/* ------------------------------------------------------------------ */
static cJSON *mount_to_json(const MountRecord *m)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "pid", (double)m->pid);
    json_add_str(obj, "device",  m->devname);
    json_add_str(obj, "path",    m->path);
    json_add_str(obj, "fstype",  m->fstype);
    json_add_str(obj, "options", m->options);
    return obj;
}

/* ------------------------------------------------------------------ */
/*  Array builder macro                                                 */
/* ------------------------------------------------------------------ */
#define BUILD_ARRAY(arr, cnt, fn) \
    do { \
        cJSON *_a = cJSON_CreateArray(); \
        for (int _i = 0; _i < (cnt); _i++) \
            cJSON_AddItemToArray(_a, fn(&(arr)[_i])); \
        cJSON_AddItemToObject(root, key, _a); \
    } while (0)

#define ADD_KV_ARRAY(parent_obj, field_key, arr, cnt) \
    do { \
        cJSON *_a = cJSON_CreateArray(); \
        for (int _i = 0; _i < (cnt); _i++) \
            cJSON_AddItemToArray(_a, kv_to_json(&(arr)[_i])); \
        cJSON_AddItemToObject((parent_obj), (field_key), _a); \
    } while (0)

#define ADD_MOD_ARRAY(parent_obj, field_key, arr, cnt) \
    do { \
        cJSON *_a = cJSON_CreateArray(); \
        for (int _i = 0; _i < (cnt); _i++) \
            cJSON_AddItemToArray(_a, module_to_json(&(arr)[_i])); \
        cJSON_AddItemToObject((parent_obj), (field_key), _a); \
    } while (0)

#define ADD_REGION_ARRAY(parent_obj, field_key, arr, cnt) \
    do { \
        cJSON *_a = cJSON_CreateArray(); \
        for (int _i = 0; _i < (cnt); _i++) \
            cJSON_AddItemToArray(_a, memregion_to_json(&(arr)[_i])); \
        cJSON_AddItemToObject((parent_obj), (field_key), _a); \
    } while (0)

#define ADD_HOOK_ARRAY(parent_obj, field_key, arr, cnt) \
    do { \
        cJSON *_a = cJSON_CreateArray(); \
        for (int _i = 0; _i < (cnt); _i++) \
            cJSON_AddItemToArray(_a, hook_to_json(&(arr)[_i])); \
        cJSON_AddItemToObject((parent_obj), (field_key), _a); \
    } while (0)

/* ------------------------------------------------------------------ */
/*  WinKernelData serializer                                            */
/* ------------------------------------------------------------------ */
static cJSON *win_kernel_data_to_json(const WinKernelData *kd)
{
    cJSON *obj = cJSON_CreateObject();

    /* os_info: windows.info.Info */
    if (kd->os_info && kd->os_info_count > 0)
        ADD_KV_ARRAY(obj, "os_info", kd->os_info, kd->os_info_count);
    else
        cJSON_AddArrayToObject(obj, "os_info");

    /* loaded_modules: windows.modules.Modules */
    if (kd->loaded_modules && kd->loaded_module_count > 0)
        ADD_MOD_ARRAY(obj, "loaded_modules",
                      kd->loaded_modules, kd->loaded_module_count);
    else
        cJSON_AddArrayToObject(obj, "loaded_modules");

    /* big_pools: windows.bigpools.BigPools */
    if (kd->big_pools && kd->big_pool_count > 0) {
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < kd->big_pool_count; i++)
            cJSON_AddItemToArray(arr, bigpool_to_json(&kd->big_pools[i]));
        cJSON_AddItemToObject(obj, "big_pools", arr);
    } else {
        cJSON_AddArrayToObject(obj, "big_pools");
    }

    /* memory_map: windows.memmap.Memmap */
    if (kd->memory_map && kd->memory_map_count > 0)
        ADD_REGION_ARRAY(obj, "memory_map",
                         kd->memory_map, kd->memory_map_count);
    else
        cJSON_AddArrayToObject(obj, "memory_map");

    /* statistics: windows.statistics.Statistics */
    if (kd->statistics && kd->statistics_count > 0)
        ADD_KV_ARRAY(obj, "statistics", kd->statistics, kd->statistics_count);
    else
        cJSON_AddArrayToObject(obj, "statistics");

    /* virtual_map: windows.virtmap.VirtMap */
    if (kd->virtual_map && kd->virtual_map_count > 0)
        ADD_REGION_ARRAY(obj, "virtual_map",
                         kd->virtual_map, kd->virtual_map_count);
    else
        cJSON_AddArrayToObject(obj, "virtual_map");

    return obj;
}

/* ------------------------------------------------------------------ */
/*  LinuxKernelData serializer                                          */
/* ------------------------------------------------------------------ */
static cJSON *lnx_kernel_data_to_json(const LinuxKernelData *kd)
{
    cJSON *obj = cJSON_CreateObject();

    /* kallsyms: linux.kallsyms.Kallsyms */
    if (kd->kallsyms && kd->kallsyms_count > 0)
        ADD_KV_ARRAY(obj, "kallsyms", kd->kallsyms, kd->kallsyms_count);
    else
        cJSON_AddArrayToObject(obj, "kallsyms");

    /* iomem: linux.iomem.IOMem */
    if (kd->iomem && kd->iomem_count > 0)
        ADD_REGION_ARRAY(obj, "iomem", kd->iomem, kd->iomem_count);
    else
        cJSON_AddArrayToObject(obj, "iomem");

    /* vmcoreinfo: linux.vmcoreinfo.VMCoreInfo */
    if (kd->vmcoreinfo && kd->vmcoreinfo_count > 0)
        ADD_KV_ARRAY(obj, "vmcoreinfo",
                     kd->vmcoreinfo, kd->vmcoreinfo_count);
    else
        cJSON_AddArrayToObject(obj, "vmcoreinfo");

    /* kernel_messages: linux.kmsg.Kmsg */
    if (kd->kernel_messages && kd->kernel_message_count > 0)
        ADD_KV_ARRAY(obj, "kernel_messages",
                     kd->kernel_messages, kd->kernel_message_count);
    else
        cJSON_AddArrayToObject(obj, "kernel_messages");

    /* boot_time: linux.boottime.Boottime */
    json_add_str(obj, "boot_time", kd->boot_time);

    /* loaded_modules: linux.lsmod.Lsmod */
    if (kd->loaded_modules && kd->loaded_module_count > 0)
        ADD_MOD_ARRAY(obj, "loaded_modules",
                      kd->loaded_modules, kd->loaded_module_count);
    else
        cJSON_AddArrayToObject(obj, "loaded_modules");

    /* kernel_threads: linux.kthreads.Kthreads */
    if (kd->kernel_threads && kd->kernel_thread_count > 0) {
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < kd->kernel_thread_count; i++)
            cJSON_AddItemToArray(arr, kthread_to_json(&kd->kernel_threads[i]));
        cJSON_AddItemToObject(obj, "kernel_threads", arr);
    } else {
        cJSON_AddArrayToObject(obj, "kernel_threads");
    }

    /* ebpf_programs: linux.ebpf.EBPF */
    if (kd->ebpf_programs && kd->ebpf_program_count > 0)
        ADD_HOOK_ARRAY(obj, "ebpf_programs",
                       kd->ebpf_programs, kd->ebpf_program_count);
    else
        cJSON_AddArrayToObject(obj, "ebpf_programs");

    /* netfilter_hooks: linux.netfilter.Netfilter */
    if (kd->netfilter_hooks && kd->netfilter_hook_count > 0)
        ADD_HOOK_ARRAY(obj, "netfilter_hooks",
                       kd->netfilter_hooks, kd->netfilter_hook_count);
    else
        cJSON_AddArrayToObject(obj, "netfilter_hooks");

    /* mount_info: linux.mountinfo.MountInfo */
    if (kd->mount_info && kd->mount_info_count > 0) {
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < kd->mount_info_count; i++)
            cJSON_AddItemToArray(arr, mount_to_json(&kd->mount_info[i]));
        cJSON_AddItemToObject(obj, "mount_info", arr);
    } else {
        cJSON_AddArrayToObject(obj, "mount_info");
    }

    return obj;
}

/* ------------------------------------------------------------------ */
/*  memscope_to_json  (main entry point)                               */
/* ------------------------------------------------------------------ */
cJSON *memscope_to_json(const ScanResult *result)
{
    cJSON *root = cJSON_CreateObject();

    /* ---- Metadata ---- */
    cJSON_AddStringToObject(root, "tool",    "RootKitChecker");
    cJSON_AddStringToObject(root, "version", MEMSCOPE_VERSION_STR);
    json_add_str(root, "scan_time",  result->scan_time);
    json_add_str(root, "image_path", result->image_path);

    /* ---- Kernel info ---- */
    cJSON_AddItemToObject(root, "kernel_info",
                          kernel_info_to_json(&result->kernel));

    /* ---- Summary ---- */
    cJSON *summary = cJSON_CreateObject();
    cJSON_AddNumberToObject(summary, "total_processes",
                            result->process_count);
    cJSON_AddNumberToObject(summary, "hidden_processes",
                            result->hidden_process_count);
    cJSON_AddNumberToObject(summary, "inactive_processes",
                            result->inactive_process_count);
    cJSON_AddNumberToObject(summary, "total_connections",
                            result->connection_count);
    cJSON_AddNumberToObject(summary, "hidden_connections",
                            result->hidden_connection_count);
    cJSON_AddNumberToObject(summary, "total_modules",
                            result->module_count);
    cJSON_AddNumberToObject(summary, "hidden_modules",
                            result->hidden_module_count);
    cJSON_AddNumberToObject(summary, "hook_count",
                            result->hook_count);
    cJSON_AddItemToObject(root, "summary", summary);

    /* ---- Detection results ---- */
    {
        const char *key = "processes";
        if (result->processes && result->process_count > 0)
            BUILD_ARRAY(result->processes, result->process_count,
                        process_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }
    {
        const char *key = "hidden_processes";
        if (result->hidden_processes && result->hidden_process_count > 0)
            BUILD_ARRAY(result->hidden_processes,
                        result->hidden_process_count, process_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }
    {
        const char *key = "inactive_processes";
        if (result->inactive_processes && result->inactive_process_count > 0)
            BUILD_ARRAY(result->inactive_processes,
                        result->inactive_process_count, process_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }
    {
        const char *key = "connections";
        if (result->connections && result->connection_count > 0)
            BUILD_ARRAY(result->connections, result->connection_count,
                        net_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }
    {
        const char *key = "hidden_connections";
        if (result->hidden_connections && result->hidden_connection_count > 0)
            BUILD_ARRAY(result->hidden_connections,
                        result->hidden_connection_count, net_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }
    {
        const char *key = "modules";
        if (result->modules && result->module_count > 0)
            BUILD_ARRAY(result->modules, result->module_count, module_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }
    {
        const char *key = "hidden_modules";
        if (result->hidden_modules && result->hidden_module_count > 0)
            BUILD_ARRAY(result->hidden_modules, result->hidden_module_count,
                        module_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }
    {
        const char *key = "hooks";
        if (result->hooks && result->hook_count > 0)
            BUILD_ARRAY(result->hooks, result->hook_count, hook_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* ---- OS-specific kernel data ---- */
    const char *os = result->kernel.os_type;
    if (os && (strcmp(os, "Windows") == 0 || strcmp(os, "windows") == 0)) {
        cJSON_AddItemToObject(root, "windows_kernel_data",
                              win_kernel_data_to_json(&result->win_kernel));
    } else if (os && (strcmp(os, "Linux") == 0 || strcmp(os, "linux") == 0)) {
        cJSON_AddItemToObject(root, "linux_kernel_data",
                              lnx_kernel_data_to_json(&result->lnx_kernel));
    } else {
        /* Include both sections when OS is unknown */
        cJSON_AddItemToObject(root, "windows_kernel_data",
                              win_kernel_data_to_json(&result->win_kernel));
        cJSON_AddItemToObject(root, "linux_kernel_data",
                              lnx_kernel_data_to_json(&result->lnx_kernel));
    }

    /* ---- Errors ---- */
    cJSON *err_arr = cJSON_CreateArray();
    for (int i = 0; i < result->error_count; i++) {
        if (result->errors[i])
            cJSON_AddItemToArray(err_arr,
                                 cJSON_CreateString(result->errors[i]));
    }
    cJSON_AddItemToObject(root, "errors", err_arr);

    return root;
}
