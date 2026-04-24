/**
 * linux_scan.c  –  Linux memory forensics detection implementation
 */

#include "linux_scan.h"
#include "py_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/*  Utility helpers (same pattern as windows_scan.c)                   */
/* ------------------------------------------------------------------ */
static const char *row_get(const PluginResult *res, const PluginRow *row,
                            const char *col_name)
{
    for (int i = 0; i < res->col_count; i++) {
        if (strcmp(res->col_names[i], col_name) == 0) {
            if (i < row->col_count && row->columns[i])
                return row->columns[i];
            return "N/A";
        }
    }
    return "N/A";
}

static void safe_copy(char *dst, size_t dsz, const char *src)
{
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, dsz - 1);
    dst[dsz - 1] = '\0';
}

static uint64_t parse_u64(const char *s)
{
    if (!s || strcmp(s, "N/A") == 0) return 0;
    return (uint64_t)strtoull(s, NULL, 0);
}

/* ------------------------------------------------------------------ */
/*  linux_get_kernel_info                                               */
/* ------------------------------------------------------------------ */
int linux_get_kernel_info(const char *image_path, KernelInfo *info)
{
    memset(info, 0, sizeof(*info));
    safe_copy(info->os_type, sizeof(info->os_type), "Linux");

    /* Try VMCoreInfo first */
    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.vmcoreinfo.VMCoreInfo", NULL);
    if (res && !res->error) {
        for (int r = 0; r < res->row_count; r++) {
            const char *key = row_get(res, &res->rows[r], "Key");
            const char *val = row_get(res, &res->rows[r], "Value");
            if (strstr(key, "OSRELEASE"))
                safe_copy(info->kernel_version,
                          sizeof(info->kernel_version), val);
            else if (strstr(key, "PAGESIZE") || strstr(key, "ARCH"))
                safe_copy(info->architecture,
                          sizeof(info->architecture), val);
        }
        pybridge_free_result(res);
    } else {
        if (res) pybridge_free_result(res);
    }

    /* Kallsyms for additional info */
    res = pybridge_run_plugin(image_path, "linux.kallsyms.Kallsyms", NULL);
    if (res && !res->error && res->row_count > 0) {
        /* Just note that kallsyms is available */
        safe_copy(info->image_type, sizeof(info->image_type),
                  "Linux Memory Image (kallsyms available)");
        pybridge_free_result(res);
    } else {
        safe_copy(info->image_type, sizeof(info->image_type),
                  "Linux Memory Image");
        if (res) pybridge_free_result(res);
    }

    if (strlen(info->architecture) == 0)
        safe_copy(info->architecture, sizeof(info->architecture), "x86_64");

    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_get_pslist                                                    */
/* ------------------------------------------------------------------ */
int linux_get_pslist(const char *image_path,
                     ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.pslist.PsList", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.pslist] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ProcessRecord *procs = calloc(res->row_count + 1, sizeof(ProcessRecord));
    if (!procs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ProcessRecord *p = &procs[r];
        p->pid  = parse_u64(row_get(res, &res->rows[r], "PID"));
        p->ppid = parse_u64(row_get(res, &res->rows[r], "PPID"));
        safe_copy(p->name, sizeof(p->name),
                  row_get(res, &res->rows[r], "COMM"));
        safe_copy(p->cmdline, sizeof(p->cmdline),
                  row_get(res, &res->rows[r], "Arguments"));
        p->offset    = parse_u64(row_get(res, &res->rows[r], "OFFSET (V)"));
        p->in_pslist = true;
        safe_copy(p->source, sizeof(p->source), "linux.pslist");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_get_psscan                                                    */
/* ------------------------------------------------------------------ */
int linux_get_psscan(const char *image_path,
                     ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.psscan.PsScan", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.psscan] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ProcessRecord *procs = calloc(res->row_count + 1, sizeof(ProcessRecord));
    if (!procs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ProcessRecord *p = &procs[r];
        p->pid  = parse_u64(row_get(res, &res->rows[r], "PID"));
        p->ppid = parse_u64(row_get(res, &res->rows[r], "PPID"));
        safe_copy(p->name, sizeof(p->name),
                  row_get(res, &res->rows[r], "COMM"));
        p->offset   = parse_u64(row_get(res, &res->rows[r], "OFFSET (V)"));
        p->in_psscan = true;
        safe_copy(p->source, sizeof(p->source), "linux.psscan");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_get_pidhashtable                                              */
/* ------------------------------------------------------------------ */
int linux_get_pidhashtable(const char *image_path,
                           ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.pidhashtable.PIDHashTable", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.pidhashtable] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ProcessRecord *procs = calloc(res->row_count + 1, sizeof(ProcessRecord));
    if (!procs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ProcessRecord *p = &procs[r];
        p->pid  = parse_u64(row_get(res, &res->rows[r], "PID"));
        p->ppid = parse_u64(row_get(res, &res->rows[r], "PPID"));
        safe_copy(p->name, sizeof(p->name),
                  row_get(res, &res->rows[r], "COMM"));
        p->offset         = parse_u64(row_get(res, &res->rows[r], "OFFSET (V)"));
        p->in_pidhashtable = true;
        safe_copy(p->source, sizeof(p->source), "linux.pidhashtable");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_detect_hidden_processes                                       */
/* ------------------------------------------------------------------ */
int linux_detect_hidden_processes(const char *image_path,
                                  ProcessRecord **out_hidden,
                                  int *out_hidden_count,
                                  ProcessRecord **out_inactive,
                                  int *out_inactive_count)
{
    *out_hidden = NULL; *out_hidden_count = 0;
    *out_inactive = NULL; *out_inactive_count = 0;

    ProcessRecord *list_procs = NULL, *scan_procs = NULL, *hash_procs = NULL;
    int list_count = 0, scan_count = 0, hash_count = 0;

    linux_get_pslist(image_path, &list_procs, &list_count);
    linux_get_psscan(image_path, &scan_procs, &scan_count);
    linux_get_pidhashtable(image_path, &hash_procs, &hash_count);

    int total_scan = scan_count + hash_count;
    ProcessRecord *hidden   = calloc(total_scan + 2, sizeof(ProcessRecord));
    ProcessRecord *inactive = calloc(total_scan + 2, sizeof(ProcessRecord));
    if (!hidden || !inactive) {
        free(hidden); free(inactive);
        free(list_procs); free(scan_procs); free(hash_procs);
        return -1;
    }

    int h_cnt = 0, i_cnt = 0;

    /* Check psscan results against pslist */
    for (int s = 0; s < scan_count; s++) {
        ProcessRecord *sp = &scan_procs[s];
        bool found = false;
        for (int l = 0; l < list_count; l++) {
            if (list_procs[l].pid == sp->pid) { found = true; break; }
        }
        if (!found) {
            /* Check if it's a zombie/inactive (pid 0 or name is empty) */
            if (sp->pid == 0 || strlen(sp->name) == 0) {
                inactive[i_cnt] = *sp;
                sp->inactive = true;
                safe_copy(inactive[i_cnt].source,
                          sizeof(inactive[i_cnt].source),
                          "linux.psscan(inactive)");
                i_cnt++;
            } else {
                hidden[h_cnt] = *sp;
                hidden[h_cnt].hidden = true;
                safe_copy(hidden[h_cnt].source,
                          sizeof(hidden[h_cnt].source),
                          "linux.psscan(hidden)");
                h_cnt++;
            }
        }
    }

    /* Check pidhashtable results against pslist */
    for (int s = 0; s < hash_count; s++) {
        ProcessRecord *hp = &hash_procs[s];
        bool found_list = false, found_hidden = false;
        for (int l = 0; l < list_count; l++) {
            if (list_procs[l].pid == hp->pid) { found_list = true; break; }
        }
        for (int hh = 0; hh < h_cnt; hh++) {
            if (hidden[hh].pid == hp->pid) { found_hidden = true; break; }
        }
        if (!found_list && !found_hidden) {
            hidden = realloc(hidden,
                             (h_cnt + 2) * sizeof(ProcessRecord));
            hidden[h_cnt] = *hp;
            hidden[h_cnt].hidden = true;
            safe_copy(hidden[h_cnt].source,
                      sizeof(hidden[h_cnt].source),
                      "linux.pidhashtable(hidden)");
            h_cnt++;
        }
    }

    *out_hidden         = hidden;
    *out_hidden_count   = h_cnt;
    *out_inactive       = inactive;
    *out_inactive_count = i_cnt;

    free(list_procs);
    free(scan_procs);
    free(hash_procs);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_get_sockstat                                                  */
/* ------------------------------------------------------------------ */
int linux_get_sockstat(const char *image_path,
                       NetRecord **out_nets, int *out_count)
{
    *out_nets = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.sockstat.Sockstat", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.sockstat] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    NetRecord *nets = calloc(res->row_count + 1, sizeof(NetRecord));
    if (!nets) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        NetRecord *n = &nets[r];
        n->pid = parse_u64(row_get(res, &res->rows[r], "NetNS"));
        safe_copy(n->proc_name, sizeof(n->proc_name),
                  row_get(res, &res->rows[r], "Process"));
        safe_copy(n->local_addr, sizeof(n->local_addr),
                  row_get(res, &res->rows[r], "Source Addr"));
        n->local_port = (int)parse_u64(
                  row_get(res, &res->rows[r], "Source Port"));
        safe_copy(n->remote_addr, sizeof(n->remote_addr),
                  row_get(res, &res->rows[r], "Dest Addr"));
        n->remote_port = (int)parse_u64(
                  row_get(res, &res->rows[r], "Dest Port"));
        safe_copy(n->proto, sizeof(n->proto),
                  row_get(res, &res->rows[r], "Type"));
        safe_copy(n->state, sizeof(n->state),
                  row_get(res, &res->rows[r], "State"));
        n->offset = parse_u64(row_get(res, &res->rows[r], "Sock Offset"));
    }

    *out_nets  = nets;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_detect_hidden_connections                                     */
/* ------------------------------------------------------------------ */
int linux_detect_hidden_connections(const char *image_path,
                                    NetRecord **out_hidden, int *out_count)
{
    /*
     * Strategy: compare sockstat (kernel socket list) against
     * lsof (process file-descriptor view).  Sockets that appear
     * in sockstat but have no associated process fd are suspicious.
     */
    *out_hidden = NULL;
    *out_count  = 0;

    NetRecord *sock_nets = NULL;
    int sock_count = 0;
    linux_get_sockstat(image_path, &sock_nets, &sock_count);

    /* Run lsof to get process-visible sockets */
    PluginResult *lsof_res = pybridge_run_plugin(
        image_path, "linux.lsof.Lsof", NULL);

    /* Build a set of socket offsets visible from lsof */
    uint64_t *lsof_offsets = NULL;
    int lsof_count = 0;
    if (lsof_res && !lsof_res->error) {
        lsof_offsets = calloc(lsof_res->row_count + 1, sizeof(uint64_t));
        for (int r = 0; r < lsof_res->row_count; r++) {
            const char *path = row_get(lsof_res, &lsof_res->rows[r], "Path");
            if (strstr(path, "socket:") || strstr(path, "sock")) {
                lsof_offsets[lsof_count++] = parse_u64(
                    row_get(lsof_res, &lsof_res->rows[r], "Offset"));
            }
        }
        pybridge_free_result(lsof_res);
    } else {
        if (lsof_res) pybridge_free_result(lsof_res);
    }

    NetRecord *hidden = calloc(sock_count + 1, sizeof(NetRecord));
    if (!hidden) {
        free(sock_nets); free(lsof_offsets);
        return -1;
    }

    int h_cnt = 0;
    for (int s = 0; s < sock_count; s++) {
        bool found = false;
        for (int l = 0; l < lsof_count; l++) {
            if (lsof_offsets[l] == sock_nets[s].offset) {
                found = true; break;
            }
        }
        /* Also consider afinfo-hidden: state is LISTEN but no process */
        if (!found && sock_count > 0) {
            hidden[h_cnt] = sock_nets[s];
            hidden[h_cnt].hidden = true;
            h_cnt++;
        }
    }

    *out_hidden = hidden;
    *out_count  = h_cnt;
    free(sock_nets);
    free(lsof_offsets);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_get_lsmod                                                     */
/* ------------------------------------------------------------------ */
int linux_get_lsmod(const char *image_path,
                    ModuleRecord **out_mods, int *out_count)
{
    *out_mods = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.lsmod.Lsmod", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.lsmod] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ModuleRecord *mods = calloc(res->row_count + 1, sizeof(ModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ModuleRecord *m = &mods[r];
        safe_copy(m->name, sizeof(m->name),
                  row_get(res, &res->rows[r], "Name"));
        m->base = parse_u64(row_get(res, &res->rows[r], "Base"));
        m->size = parse_u64(row_get(res, &res->rows[r], "Size"));
        safe_copy(m->source, sizeof(m->source), "linux.lsmod");
    }

    *out_mods  = mods;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_detect_hidden_modules                                         */
/* ------------------------------------------------------------------ */
int linux_detect_hidden_modules(const char *image_path,
                                ModuleRecord **out_hidden, int *out_count)
{
    *out_hidden = NULL;
    *out_count  = 0;

    /* Use the dedicated hidden_modules plugin */
    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.hidden_modules.Hidden_modules", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.hidden_modules] %s\n", res->error);
            pybridge_free_result(res);
        }
        /* Fallback: modxview cross-view */
        res = pybridge_run_plugin(
            image_path, "linux.modxview.Modxview", NULL);
        if (!res || res->error) {
            if (res) pybridge_free_result(res);
            return -1;
        }
    }

    ModuleRecord *mods = calloc(res->row_count + 1, sizeof(ModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    int m_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        /* hidden_modules only returns hidden entries */
        ModuleRecord *m = &mods[m_cnt];
        safe_copy(m->name, sizeof(m->name),
                  row_get(res, &res->rows[r], "Name"));
        m->base   = parse_u64(row_get(res, &res->rows[r], "Base"));
        m->size   = parse_u64(row_get(res, &res->rows[r], "Size"));
        m->hidden = true;
        safe_copy(m->source, sizeof(m->source),
                  "linux.hidden_modules");
        m_cnt++;
    }

    *out_hidden = mods;
    *out_count  = m_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_get_syscall_hooks                                             */
/* ------------------------------------------------------------------ */
int linux_get_syscall_hooks(const char *image_path,
                             HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.check_syscall.Check_syscall", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.check_syscall] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count + 1, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        const char *is_hooked = row_get(res, &res->rows[r], "IsHooked");
        /* Include all entries; mark hooked ones */
        HookRecord *h = &hooks[h_cnt];
        h->index = (uint32_t)parse_u64(
                   row_get(res, &res->rows[r], "Index"));
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Symbol"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "HandlerAddress"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Module"));
        h->hooked = (strcmp(is_hooked, "True") == 0 ||
                     strcmp(is_hooked, "true") == 0 ||
                     strcmp(is_hooked, "1")    == 0);
        safe_copy(h->hook_type, sizeof(h->hook_type), "syscall");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_get_idt_hooks                                                 */
/* ------------------------------------------------------------------ */
int linux_get_idt_hooks(const char *image_path,
                         HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.check_idt.Check_idt", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.check_idt] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count + 1, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        HookRecord *h = &hooks[h_cnt];
        h->index = (uint32_t)parse_u64(
                   row_get(res, &res->rows[r], "Index"));
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Symbol"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "HandlerAddress"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Module"));
        const char *is_hooked = row_get(res, &res->rows[r], "IsHooked");
        h->hooked = (strcmp(is_hooked, "True") == 0 ||
                     strcmp(is_hooked, "true") == 0 ||
                     strcmp(is_hooked, "1")    == 0);
        safe_copy(h->hook_type, sizeof(h->hook_type), "IDT");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_check_afinfo                                                  */
/* ------------------------------------------------------------------ */
int linux_check_afinfo(const char *image_path,
                        HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.check_afinfo.Check_afinfo", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.check_afinfo] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count + 1, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        HookRecord *h = &hooks[h_cnt];
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Symbol"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "HandlerAddress"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Module"));
        h->hooked = true;
        safe_copy(h->hook_type, sizeof(h->hook_type), "afinfo");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_check_creds                                                   */
/* ------------------------------------------------------------------ */
int linux_check_creds(const char *image_path,
                       ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.check_creds.Check_creds", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.check_creds] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ProcessRecord *procs = calloc(res->row_count + 1, sizeof(ProcessRecord));
    if (!procs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ProcessRecord *p = &procs[r];
        p->pid = parse_u64(row_get(res, &res->rows[r], "PID"));
        safe_copy(p->name, sizeof(p->name),
                  row_get(res, &res->rows[r], "Process"));
        p->hidden = true;   /* cred anomaly = suspicious */
        safe_copy(p->source, sizeof(p->source), "linux.check_creds");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_check_ebpf                                                    */
/* ------------------------------------------------------------------ */
int linux_check_ebpf(const char *image_path,
                      HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.ebpf.EBPF", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.ebpf] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count + 1, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        HookRecord *h = &hooks[h_cnt];
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Name"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "LoadTime"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Tag"));
        h->hooked = true;
        safe_copy(h->hook_type, sizeof(h->hook_type), "eBPF");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_check_netfilter                                               */
/* ------------------------------------------------------------------ */
int linux_check_netfilter(const char *image_path,
                           HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.netfilter.Netfilter", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.netfilter] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count + 1, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        HookRecord *h = &hooks[h_cnt];
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Hook"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "Handler"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Module"));
        h->hooked = true;
        safe_copy(h->hook_type, sizeof(h->hook_type), "netfilter");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_check_tty                                                     */
/* ------------------------------------------------------------------ */
int linux_check_tty(const char *image_path,
                     HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.tty_check.tty_check", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.tty_check] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count + 1, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        HookRecord *h = &hooks[h_cnt];
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Name"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "Address"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Module"));
        h->hooked = true;
        safe_copy(h->hook_type, sizeof(h->hook_type), "tty_hook");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_check_keyboard_notifiers                                      */
/* ------------------------------------------------------------------ */
int linux_check_keyboard_notifiers(const char *image_path,
                                    HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "linux.keyboard_notifiers.Keyboard_notifiers", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[linux.keyboard_notifiers] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count + 1, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        HookRecord *h = &hooks[h_cnt];
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Symbol"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "HandlerAddress"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Module"));
        h->hooked = true;
        safe_copy(h->hook_type, sizeof(h->hook_type), "keyboard_notifier");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  linux_full_scan                                                     */
/* ------------------------------------------------------------------ */
int linux_full_scan(const char *image_path, ScanResult *result)
{
    /* 1. Kernel info */
    linux_get_kernel_info(image_path, &result->kernel);

    /* 2. All processes */
    linux_get_pslist(image_path,
                     &result->processes, &result->process_count);

    /* 3. Hidden + inactive processes */
    linux_detect_hidden_processes(image_path,
        &result->hidden_processes,   &result->hidden_process_count,
        &result->inactive_processes, &result->inactive_process_count);

    /* 4. Network connections */
    linux_get_sockstat(image_path,
                       &result->connections, &result->connection_count);

    /* 5. Hidden connections */
    linux_detect_hidden_connections(image_path,
        &result->hidden_connections, &result->hidden_connection_count);

    /* 6. Kernel modules */
    linux_get_lsmod(image_path,
                    &result->modules, &result->module_count);

    /* 7. Hidden modules */
    linux_detect_hidden_modules(image_path,
        &result->hidden_modules, &result->hidden_module_count);

    /* 8. Syscall hooks */
    HookRecord *sc_hooks = NULL; int sc_count = 0;
    linux_get_syscall_hooks(image_path, &sc_hooks, &sc_count);

    /* 9. IDT hooks */
    HookRecord *idt_hooks = NULL; int idt_count = 0;
    linux_get_idt_hooks(image_path, &idt_hooks, &idt_count);

    /* 10. Afinfo hooks */
    HookRecord *af_hooks = NULL; int af_count = 0;
    linux_check_afinfo(image_path, &af_hooks, &af_count);

    /* 11. eBPF */
    HookRecord *ebpf_hooks = NULL; int ebpf_count = 0;
    linux_check_ebpf(image_path, &ebpf_hooks, &ebpf_count);

    /* 12. Netfilter */
    HookRecord *nf_hooks = NULL; int nf_count = 0;
    linux_check_netfilter(image_path, &nf_hooks, &nf_count);

    /* 13. TTY */
    HookRecord *tty_hooks = NULL; int tty_count = 0;
    linux_check_tty(image_path, &tty_hooks, &tty_count);

    /* 14. Keyboard notifiers */
    HookRecord *kb_hooks = NULL; int kb_count = 0;
    linux_check_keyboard_notifiers(image_path, &kb_hooks, &kb_count);

    /* Merge all hooks */
    int total_hooks = sc_count + idt_count + af_count +
                      ebpf_count + nf_count + tty_count + kb_count;
    result->hooks = calloc(total_hooks + 1, sizeof(HookRecord));
    if (result->hooks) {
        int off = 0;
#define MERGE_HOOKS(arr, cnt) \
        if (arr) { memcpy(result->hooks + off, arr, (cnt)*sizeof(HookRecord)); \
                   off += (cnt); free(arr); }
        MERGE_HOOKS(sc_hooks,  sc_count);
        MERGE_HOOKS(idt_hooks, idt_count);
        MERGE_HOOKS(af_hooks,  af_count);
        MERGE_HOOKS(ebpf_hooks, ebpf_count);
        MERGE_HOOKS(nf_hooks,  nf_count);
        MERGE_HOOKS(tty_hooks, tty_count);
        MERGE_HOOKS(kb_hooks,  kb_count);
#undef MERGE_HOOKS
        result->hook_count = off;
    }

    /* 15. Credential anomalies → merge into hidden_processes */
    ProcessRecord *cred_procs = NULL; int cred_count = 0;
    if (linux_check_creds(image_path, &cred_procs, &cred_count) == 0
        && cred_count > 0)
    {
        int new_total = result->hidden_process_count + cred_count;
        result->hidden_processes = realloc(result->hidden_processes,
                                           new_total * sizeof(ProcessRecord));
        memcpy(result->hidden_processes + result->hidden_process_count,
               cred_procs, cred_count * sizeof(ProcessRecord));
        result->hidden_process_count = new_total;
        free(cred_procs);
    }

    return 0;
}
