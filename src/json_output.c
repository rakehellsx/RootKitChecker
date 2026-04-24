/**
 * json_output.c  –  Serialize ScanResult to cJSON
 */

#include "memscope.h"
#include "../../third_party/cjson/cJSON.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Helper: add a string field, replacing empty / N/A with null        */
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
/*  Serialize KernelInfo                                                */
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
/*  Serialize ProcessRecord                                             */
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
/*  Serialize NetRecord                                                 */
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
/*  Serialize ModuleRecord                                              */
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
/*  Serialize HookRecord                                                */
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
/*  Build a JSON array from a generic array                            */
/* ------------------------------------------------------------------ */
#define BUILD_ARRAY(arr, cnt, fn) \
    do { \
        cJSON *_a = cJSON_CreateArray(); \
        for (int _i = 0; _i < (cnt); _i++) \
            cJSON_AddItemToArray(_a, fn(&(arr)[_i])); \
        cJSON_AddItemToObject(root, key, _a); \
    } while (0)

/* ------------------------------------------------------------------ */
/*  memscope_to_json                                                    */
/* ------------------------------------------------------------------ */
cJSON *memscope_to_json(const ScanResult *result)
{
    cJSON *root = cJSON_CreateObject();

    /* Metadata */
    cJSON_AddStringToObject(root, "tool",    "memscope");
    cJSON_AddStringToObject(root, "version", MEMSCOPE_VERSION_STR);
    json_add_str(root, "scan_time",  result->scan_time);
    json_add_str(root, "image_path", result->image_path);

    /* Kernel info */
    cJSON_AddItemToObject(root, "kernel_info",
                          kernel_info_to_json(&result->kernel));

    /* Summary */
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

    /* Processes */
    {
        const char *key = "processes";
        if (result->processes && result->process_count > 0)
            BUILD_ARRAY(result->processes, result->process_count,
                        process_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Hidden processes */
    {
        const char *key = "hidden_processes";
        if (result->hidden_processes && result->hidden_process_count > 0)
            BUILD_ARRAY(result->hidden_processes,
                        result->hidden_process_count, process_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Inactive processes */
    {
        const char *key = "inactive_processes";
        if (result->inactive_processes && result->inactive_process_count > 0)
            BUILD_ARRAY(result->inactive_processes,
                        result->inactive_process_count, process_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Network connections */
    {
        const char *key = "connections";
        if (result->connections && result->connection_count > 0)
            BUILD_ARRAY(result->connections, result->connection_count,
                        net_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Hidden connections */
    {
        const char *key = "hidden_connections";
        if (result->hidden_connections && result->hidden_connection_count > 0)
            BUILD_ARRAY(result->hidden_connections,
                        result->hidden_connection_count, net_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Kernel modules */
    {
        const char *key = "modules";
        if (result->modules && result->module_count > 0)
            BUILD_ARRAY(result->modules, result->module_count, module_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Hidden modules */
    {
        const char *key = "hidden_modules";
        if (result->hidden_modules && result->hidden_module_count > 0)
            BUILD_ARRAY(result->hidden_modules, result->hidden_module_count,
                        module_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Hooks */
    {
        const char *key = "hooks";
        if (result->hooks && result->hook_count > 0)
            BUILD_ARRAY(result->hooks, result->hook_count, hook_to_json);
        else
            cJSON_AddArrayToObject(root, key);
    }

    /* Errors */
    cJSON *err_arr = cJSON_CreateArray();
    for (int i = 0; i < result->error_count; i++) {
        if (result->errors[i])
            cJSON_AddItemToArray(err_arr,
                                 cJSON_CreateString(result->errors[i]));
    }
    cJSON_AddItemToObject(root, "errors", err_arr);

    return root;
}
