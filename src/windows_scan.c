/**
 * windows_scan.c  –  Windows memory forensics detection implementation
 */

#include "windows_scan.h"
#include "py_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/*  Utility: safe string copy from a PluginRow column by name          */
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
/*  windows_get_kernel_info                                             */
/* ------------------------------------------------------------------ */
int windows_get_kernel_info(const char *image_path, KernelInfo *info)
{
    memset(info, 0, sizeof(*info));
    safe_copy(info->os_type, sizeof(info->os_type), "Windows");

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.info.Info", NULL);
    if (!res) return -1;
    if (res->error) {
        fprintf(stderr, "[windows_info] %s\n", res->error);
        pybridge_free_result(res);
        return -1;
    }

    for (int r = 0; r < res->row_count; r++) {
        const char *var = row_get(res, &res->rows[r], "Variable");
        const char *val = row_get(res, &res->rows[r], "Value");
        if (!var || !val) continue;

        if (strstr(var, "NtBuildLab") || strstr(var, "NtBuildLabEx"))
            safe_copy(info->build_str, sizeof(info->build_str), val);
        else if (strstr(var, "NtMajorVersion") || strstr(var, "NtMinorVersion"))
            ; /* combined elsewhere */
        else if (strstr(var, "PE MajorOperatingSystemVersion"))
            safe_copy(info->os_version, sizeof(info->os_version), val);
        else if (strstr(var, "Symbols"))
            ; /* ignore */
        else if (strstr(var, "Is64Bit"))
            safe_copy(info->architecture, sizeof(info->architecture),
                      strcmp(val, "True") == 0 ? "x86_64" : "x86");
        else if (strstr(var, "DTB"))
            info->dtb = parse_u64(val);
        else if (strstr(var, "KDBG"))
            info->kdbg_offset = parse_u64(val);
    }

    safe_copy(info->image_type, sizeof(info->image_type), "Windows Memory Image");
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_pslist                                                  */
/* ------------------------------------------------------------------ */
int windows_get_pslist(const char *image_path,
                       ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.pslist.PsList", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[pslist] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ProcessRecord *procs = calloc(res->row_count, sizeof(ProcessRecord));
    if (!procs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ProcessRecord *p = &procs[r];
        p->pid   = parse_u64(row_get(res, &res->rows[r], "PID"));
        p->ppid  = parse_u64(row_get(res, &res->rows[r], "PPID"));
        safe_copy(p->name,        sizeof(p->name),
                  row_get(res, &res->rows[r], "ImageFileName"));
        safe_copy(p->create_time, sizeof(p->create_time),
                  row_get(res, &res->rows[r], "CreateTime"));
        safe_copy(p->exit_time,   sizeof(p->exit_time),
                  row_get(res, &res->rows[r], "ExitTime"));
        p->offset     = parse_u64(row_get(res, &res->rows[r], "OFFSET (V)"));
        p->in_pslist  = true;
        p->inactive   = (strcmp(p->exit_time, "N/A") != 0 &&
                         strlen(p->exit_time) > 2);
        safe_copy(p->source, sizeof(p->source), "pslist");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_psscan                                                  */
/* ------------------------------------------------------------------ */
int windows_get_psscan(const char *image_path,
                       ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.psscan.PsScan", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[psscan] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ProcessRecord *procs = calloc(res->row_count, sizeof(ProcessRecord));
    if (!procs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ProcessRecord *p = &procs[r];
        p->pid   = parse_u64(row_get(res, &res->rows[r], "PID"));
        p->ppid  = parse_u64(row_get(res, &res->rows[r], "PPID"));
        safe_copy(p->name,        sizeof(p->name),
                  row_get(res, &res->rows[r], "ImageFileName"));
        safe_copy(p->create_time, sizeof(p->create_time),
                  row_get(res, &res->rows[r], "CreateTime"));
        safe_copy(p->exit_time,   sizeof(p->exit_time),
                  row_get(res, &res->rows[r], "ExitTime"));
        p->offset      = parse_u64(row_get(res, &res->rows[r], "OFFSET (P)"));
        p->in_psscan   = true;
        p->inactive    = (strcmp(p->exit_time, "N/A") != 0 &&
                          strlen(p->exit_time) > 2);
        safe_copy(p->source, sizeof(p->source), "psscan");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_psxview                                                 */
/* ------------------------------------------------------------------ */
int windows_get_psxview(const char *image_path,
                        ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.psxview.PsXView", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[psxview] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ProcessRecord *procs = calloc(res->row_count, sizeof(ProcessRecord));
    if (!procs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ProcessRecord *p = &procs[r];
        p->pid  = parse_u64(row_get(res, &res->rows[r], "PID"));
        safe_copy(p->name, sizeof(p->name),
                  row_get(res, &res->rows[r], "ImageFileName"));
        p->offset = parse_u64(row_get(res, &res->rows[r], "Offset"));

        /* PsXView columns: pslist, psscan, thrdproc, pspcid, csrss … */
        const char *pslist_col = row_get(res, &res->rows[r], "pslist");
        const char *psscan_col = row_get(res, &res->rows[r], "psscan");
        p->in_pslist  = (strcmp(pslist_col, "True") == 0);
        p->in_psscan  = (strcmp(psscan_col, "True") == 0);

        /* Hidden: visible in at least one source but not in pslist */
        p->hidden = (!p->in_pslist && p->in_psscan);
        safe_copy(p->source, sizeof(p->source), "psxview");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_detect_hidden_processes                                     */
/* ------------------------------------------------------------------ */
int windows_detect_hidden_processes(const char *image_path,
                                    ProcessRecord **out_hidden,
                                    int *out_hidden_count,
                                    ProcessRecord **out_inactive,
                                    int *out_inactive_count)
{
    *out_hidden = NULL; *out_hidden_count = 0;
    *out_inactive = NULL; *out_inactive_count = 0;

    ProcessRecord *list_procs = NULL, *scan_procs = NULL;
    int list_count = 0, scan_count = 0;

    windows_get_pslist(image_path, &list_procs, &list_count);
    windows_get_psscan(image_path, &scan_procs, &scan_count);

    /* Allocate worst-case buffers */
    ProcessRecord *hidden   = calloc(scan_count + 1, sizeof(ProcessRecord));
    ProcessRecord *inactive = calloc(scan_count + 1, sizeof(ProcessRecord));
    if (!hidden || !inactive) {
        free(hidden); free(inactive);
        free(list_procs); free(scan_procs);
        return -1;
    }

    int h_cnt = 0, i_cnt = 0;

    for (int s = 0; s < scan_count; s++) {
        ProcessRecord *sp = &scan_procs[s];

        /* Check if this PID+offset appears in pslist */
        bool found_in_list = false;
        for (int l = 0; l < list_count; l++) {
            if (list_procs[l].pid == sp->pid) {
                found_in_list = true;
                break;
            }
        }

        if (sp->inactive) {
            inactive[i_cnt] = *sp;
            safe_copy(inactive[i_cnt].source,
                      sizeof(inactive[i_cnt].source), "psscan(inactive)");
            i_cnt++;
        } else if (!found_in_list) {
            hidden[h_cnt] = *sp;
            hidden[h_cnt].hidden = true;
            safe_copy(hidden[h_cnt].source,
                      sizeof(hidden[h_cnt].source), "psscan(hidden)");
            h_cnt++;
        }
    }

    /* Also check PsXView for additional hidden processes */
    ProcessRecord *xview_procs = NULL;
    int xview_count = 0;
    if (windows_get_psxview(image_path, &xview_procs, &xview_count) == 0) {
        for (int x = 0; x < xview_count; x++) {
            if (!xview_procs[x].hidden) continue;
            /* Avoid duplicates */
            bool dup = false;
            for (int hh = 0; hh < h_cnt; hh++) {
                if (hidden[hh].pid == xview_procs[x].pid) { dup = true; break; }
            }
            if (!dup) {
                hidden = realloc(hidden,
                                 (h_cnt + 2) * sizeof(ProcessRecord));
                hidden[h_cnt] = xview_procs[x];
                safe_copy(hidden[h_cnt].source,
                          sizeof(hidden[h_cnt].source), "psxview(hidden)");
                h_cnt++;
            }
        }
        free(xview_procs);
    }

    *out_hidden        = hidden;
    *out_hidden_count  = h_cnt;
    *out_inactive      = inactive;
    *out_inactive_count = i_cnt;

    free(list_procs);
    free(scan_procs);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_netscan                                                 */
/* ------------------------------------------------------------------ */
int windows_get_netscan(const char *image_path,
                        NetRecord **out_nets, int *out_count)
{
    *out_nets = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.netscan.NetScan", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[netscan] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    NetRecord *nets = calloc(res->row_count, sizeof(NetRecord));
    if (!nets) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        NetRecord *n = &nets[r];
        n->pid = parse_u64(row_get(res, &res->rows[r], "PID"));
        safe_copy(n->proc_name,   sizeof(n->proc_name),
                  row_get(res, &res->rows[r], "Owner"));
        safe_copy(n->local_addr,  sizeof(n->local_addr),
                  row_get(res, &res->rows[r], "LocalAddr"));
        n->local_port = (int)parse_u64(
                  row_get(res, &res->rows[r], "LocalPort"));
        safe_copy(n->remote_addr, sizeof(n->remote_addr),
                  row_get(res, &res->rows[r], "ForeignAddr"));
        n->remote_port = (int)parse_u64(
                  row_get(res, &res->rows[r], "ForeignPort"));
        safe_copy(n->proto, sizeof(n->proto),
                  row_get(res, &res->rows[r], "Proto"));
        safe_copy(n->state, sizeof(n->state),
                  row_get(res, &res->rows[r], "State"));
        n->offset = parse_u64(row_get(res, &res->rows[r], "Offset"));
    }

    *out_nets  = nets;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_netstat                                                 */
/* ------------------------------------------------------------------ */
int windows_get_netstat(const char *image_path,
                        NetRecord **out_nets, int *out_count)
{
    *out_nets = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.netstat.NetStat", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[netstat] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    NetRecord *nets = calloc(res->row_count, sizeof(NetRecord));
    if (!nets) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        NetRecord *n = &nets[r];
        n->pid = parse_u64(row_get(res, &res->rows[r], "PID"));
        safe_copy(n->proc_name,   sizeof(n->proc_name),
                  row_get(res, &res->rows[r], "Owner"));
        safe_copy(n->local_addr,  sizeof(n->local_addr),
                  row_get(res, &res->rows[r], "LocalAddr"));
        n->local_port = (int)parse_u64(
                  row_get(res, &res->rows[r], "LocalPort"));
        safe_copy(n->remote_addr, sizeof(n->remote_addr),
                  row_get(res, &res->rows[r], "ForeignAddr"));
        n->remote_port = (int)parse_u64(
                  row_get(res, &res->rows[r], "ForeignPort"));
        safe_copy(n->proto, sizeof(n->proto),
                  row_get(res, &res->rows[r], "Proto"));
        safe_copy(n->state, sizeof(n->state),
                  row_get(res, &res->rows[r], "State"));
        n->offset = parse_u64(row_get(res, &res->rows[r], "Offset"));
    }

    *out_nets  = nets;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_detect_hidden_connections                                   */
/* ------------------------------------------------------------------ */
int windows_detect_hidden_connections(const char *image_path,
                                      NetRecord **out_hidden, int *out_count)
{
    *out_hidden = NULL;
    *out_count  = 0;

    NetRecord *scan_nets = NULL, *stat_nets = NULL;
    int scan_count = 0, stat_count = 0;

    windows_get_netscan(image_path, &scan_nets, &scan_count);
    windows_get_netstat(image_path, &stat_nets, &stat_count);

    NetRecord *hidden = calloc(scan_count + 1, sizeof(NetRecord));
    if (!hidden) {
        free(scan_nets); free(stat_nets);
        return -1;
    }

    int h_cnt = 0;
    for (int s = 0; s < scan_count; s++) {
        bool found = false;
        for (int t = 0; t < stat_count; t++) {
            if (scan_nets[s].offset == stat_nets[t].offset) {
                found = true; break;
            }
        }
        if (!found) {
            hidden[h_cnt] = scan_nets[s];
            hidden[h_cnt].hidden = true;
            h_cnt++;
        }
    }

    *out_hidden = hidden;
    *out_count  = h_cnt;
    free(scan_nets);
    free(stat_nets);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_modules                                                 */
/* ------------------------------------------------------------------ */
int windows_get_modules(const char *image_path,
                        ModuleRecord **out_mods, int *out_count)
{
    *out_mods = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.modules.Modules", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[modules] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ModuleRecord *mods = calloc(res->row_count, sizeof(ModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ModuleRecord *m = &mods[r];
        safe_copy(m->name, sizeof(m->name),
                  row_get(res, &res->rows[r], "Name"));
        m->base = parse_u64(row_get(res, &res->rows[r], "Base"));
        m->size = parse_u64(row_get(res, &res->rows[r], "Size"));
        safe_copy(m->path, sizeof(m->path),
                  row_get(res, &res->rows[r], "File output"));
        safe_copy(m->source, sizeof(m->source), "modules");
    }

    *out_mods  = mods;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_modscan                                                 */
/* ------------------------------------------------------------------ */
int windows_get_modscan(const char *image_path,
                        ModuleRecord **out_mods, int *out_count)
{
    *out_mods = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.modscan.ModScan", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[modscan] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ModuleRecord *mods = calloc(res->row_count, sizeof(ModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ModuleRecord *m = &mods[r];
        safe_copy(m->name, sizeof(m->name),
                  row_get(res, &res->rows[r], "Name"));
        m->base = parse_u64(row_get(res, &res->rows[r], "Base"));
        m->size = parse_u64(row_get(res, &res->rows[r], "Size"));
        safe_copy(m->path, sizeof(m->path),
                  row_get(res, &res->rows[r], "File output"));
        safe_copy(m->source, sizeof(m->source), "modscan");
    }

    *out_mods  = mods;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_driverscan                                              */
/* ------------------------------------------------------------------ */
int windows_get_driverscan(const char *image_path,
                            ModuleRecord **out_mods, int *out_count)
{
    *out_mods = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.driverscan.DriverScan", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[driverscan] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ModuleRecord *mods = calloc(res->row_count, sizeof(ModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ModuleRecord *m = &mods[r];
        safe_copy(m->name, sizeof(m->name),
                  row_get(res, &res->rows[r], "Name"));
        m->base = parse_u64(row_get(res, &res->rows[r], "Start"));
        m->size = parse_u64(row_get(res, &res->rows[r], "Size"));
        safe_copy(m->path, sizeof(m->path),
                  row_get(res, &res->rows[r], "ServiceKey"));
        safe_copy(m->source, sizeof(m->source), "driverscan");
    }

    *out_mods  = mods;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_detect_hidden_modules                                       */
/* ------------------------------------------------------------------ */
int windows_detect_hidden_modules(const char *image_path,
                                  ModuleRecord **out_hidden, int *out_count)
{
    *out_hidden = NULL;
    *out_count  = 0;

    ModuleRecord *list_mods = NULL, *scan_mods = NULL;
    int list_count = 0, scan_count = 0;

    windows_get_modules(image_path, &list_mods, &list_count);
    windows_get_modscan(image_path, &scan_mods, &scan_count);

    ModuleRecord *hidden = calloc(scan_count + 1, sizeof(ModuleRecord));
    if (!hidden) {
        free(list_mods); free(scan_mods);
        return -1;
    }

    int h_cnt = 0;
    for (int s = 0; s < scan_count; s++) {
        bool found = false;
        for (int l = 0; l < list_count; l++) {
            if (scan_mods[s].base == list_mods[l].base) {
                found = true; break;
            }
        }
        if (!found) {
            hidden[h_cnt] = scan_mods[s];
            hidden[h_cnt].hidden = true;
            safe_copy(hidden[h_cnt].source,
                      sizeof(hidden[h_cnt].source), "modscan(hidden)");
            h_cnt++;
        }
    }

    *out_hidden = hidden;
    *out_count  = h_cnt;
    free(list_mods);
    free(scan_mods);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_get_ssdt_hooks                                              */
/* ------------------------------------------------------------------ */
int windows_get_ssdt_hooks(const char *image_path,
                            HookRecord **out_hooks, int *out_count)
{
    *out_hooks = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.ssdt.SSDT", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[ssdt] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    HookRecord *hooks = calloc(res->row_count, sizeof(HookRecord));
    if (!hooks) { pybridge_free_result(res); return -1; }

    int h_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        HookRecord *h = &hooks[h_cnt];
        h->index = (uint32_t)parse_u64(
                   row_get(res, &res->rows[r], "Index"));
        safe_copy(h->symbol, sizeof(h->symbol),
                  row_get(res, &res->rows[r], "Symbol"));
        h->handler_addr = parse_u64(
                   row_get(res, &res->rows[r], "Address"));
        safe_copy(h->module, sizeof(h->module),
                  row_get(res, &res->rows[r], "Module"));

        /* Mark as hooked if module is not ntoskrnl / win32k */
        const char *mod = h->module;
        h->hooked = (strstr(mod, "ntoskrnl") == NULL &&
                     strstr(mod, "win32k")   == NULL &&
                     strstr(mod, "N/A")      == NULL &&
                     strlen(mod) > 0);
        safe_copy(h->hook_type, sizeof(h->hook_type), "SSDT");
        h_cnt++;
    }

    *out_hooks = hooks;
    *out_count = h_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_detect_hollow_processes                                     */
/* ------------------------------------------------------------------ */
int windows_detect_hollow_processes(const char *image_path,
                                    ProcessRecord **out_procs, int *out_count)
{
    *out_procs = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.hollowprocesses.HollowProcesses", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[hollowprocesses] %s\n", res->error);
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
        p->hidden = true;
        safe_copy(p->source, sizeof(p->source), "hollowprocesses");
    }

    *out_procs = procs;
    *out_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_detect_driver_anomalies                                     */
/* ------------------------------------------------------------------ */
int windows_detect_driver_anomalies(const char *image_path,
                                    ModuleRecord **out_mods, int *out_count)
{
    *out_mods = NULL;
    *out_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.drivermodule.DriverModule", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[drivermodule] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ModuleRecord *mods = calloc(res->row_count + 1, sizeof(ModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    int m_cnt = 0;
    for (int r = 0; r < res->row_count; r++) {
        /* Only include entries flagged as anomalous */
        const char *module_name = row_get(res, &res->rows[r], "DriverName");
        const char *base_str    = row_get(res, &res->rows[r], "Base");
        ModuleRecord *m = &mods[m_cnt];
        safe_copy(m->name, sizeof(m->name), module_name);
        m->base   = parse_u64(base_str);
        m->hidden = true;
        safe_copy(m->source, sizeof(m->source), "drivermodule(anomaly)");
        m_cnt++;
    }

    *out_mods  = mods;
    *out_count = m_cnt;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_full_scan                                                   */
/* ------------------------------------------------------------------ */
int windows_full_scan(const char *image_path, ScanResult *result)
{
    int rc = 0;

    /* 1. Kernel info */
    windows_get_kernel_info(image_path, &result->kernel);

    /* 2. All processes (pslist) */
    rc = windows_get_pslist(image_path,
                            &result->processes, &result->process_count);
    if (rc != 0)
        fprintf(stderr, "[windows_full_scan] pslist failed\n");

    /* 3. Hidden + inactive processes */
    windows_detect_hidden_processes(image_path,
        &result->hidden_processes,   &result->hidden_process_count,
        &result->inactive_processes, &result->inactive_process_count);

    /* 4. Network connections */
    windows_get_netscan(image_path,
                        &result->connections, &result->connection_count);

    /* 5. Hidden network connections */
    windows_detect_hidden_connections(image_path,
        &result->hidden_connections, &result->hidden_connection_count);

    /* 6. Kernel modules */
    windows_get_modules(image_path,
                        &result->modules, &result->module_count);

    /* 7. Hidden modules */
    windows_detect_hidden_modules(image_path,
        &result->hidden_modules, &result->hidden_module_count);

    /* 8. SSDT hooks */
    windows_get_ssdt_hooks(image_path,
                           &result->hooks, &result->hook_count);

    /* 9. Hollow processes – merge into hidden_processes list */
    ProcessRecord *hollow = NULL;
    int hollow_count = 0;
    if (windows_detect_hollow_processes(image_path,
                                        &hollow, &hollow_count) == 0
        && hollow_count > 0)
    {
        int new_total = result->hidden_process_count + hollow_count;
        result->hidden_processes = realloc(result->hidden_processes,
                                           new_total * sizeof(ProcessRecord));
        memcpy(result->hidden_processes + result->hidden_process_count,
               hollow, hollow_count * sizeof(ProcessRecord));
        result->hidden_process_count = new_total;
        free(hollow);
    }

    return 0;
}
