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

    /* 10. Kernel data collection (os_info, modules, bigpools,
     *     memmap, statistics, virtmap) */
    windows_collect_kernel_data(image_path, &result->win_kernel);

    return 0;
}

/* ================================================================== */
/*  Windows kernel data collection functions                           */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  windows_collect_os_info  (windows.info.Info)                       */
/* ------------------------------------------------------------------ */
int windows_collect_os_info(const char *image_path, WinKernelData *kd)
{
    kd->os_info       = NULL;
    kd->os_info_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.info.Info", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.info] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    KVRecord *recs = calloc(res->row_count + 1, sizeof(KVRecord));
    if (!recs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        safe_copy(recs[r].key,   sizeof(recs[r].key),
                  row_get(res, &res->rows[r], "Variable"));
        safe_copy(recs[r].value, sizeof(recs[r].value),
                  row_get(res, &res->rows[r], "Value"));
    }

    kd->os_info       = recs;
    kd->os_info_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_loaded_modules  (windows.modules.Modules)          */
/* ------------------------------------------------------------------ */
int windows_collect_loaded_modules(const char *image_path, WinKernelData *kd)
{
    kd->loaded_modules      = NULL;
    kd->loaded_module_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.modules.Modules", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.modules] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ModuleRecord *mods = calloc(res->row_count + 1, sizeof(ModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        safe_copy(mods[r].name, sizeof(mods[r].name),
                  row_get(res, &res->rows[r], "Name"));
        mods[r].base = parse_u64(row_get(res, &res->rows[r], "Base"));
        mods[r].size = parse_u64(row_get(res, &res->rows[r], "Size"));
        safe_copy(mods[r].path, sizeof(mods[r].path),
                  row_get(res, &res->rows[r], "Path"));
        safe_copy(mods[r].source, sizeof(mods[r].source),
                  "windows.modules");
    }

    kd->loaded_modules      = mods;
    kd->loaded_module_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_big_pools  (windows.bigpools.BigPools)             */
/* ------------------------------------------------------------------ */
int windows_collect_big_pools(const char *image_path, WinKernelData *kd)
{
    kd->big_pools      = NULL;
    kd->big_pool_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.bigpools.BigPools", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.bigpools] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    BigPoolRecord *pools = calloc(res->row_count + 1, sizeof(BigPoolRecord));
    if (!pools) { pybridge_free_result(res); return -1; }

    /* Known legitimate pool tags (partial list for heuristic check) */
    static const char *known_tags[] = {
        "MmSt", "Ntff", "FMfn", "File", "Driv", "ObNm",
        "Proc", "Thre", "Even", "Muta", "Sema", "Port",
        "AlPC", "Pipe", "Recy", "Vad ", "VadS", "VadL",
        NULL
    };

    for (int r = 0; r < res->row_count; r++) {
        BigPoolRecord *p = &pools[r];
        p->virtual_addr = parse_u64(row_get(res, &res->rows[r], "PoolBigPageTable"));
        p->size         = parse_u64(row_get(res, &res->rows[r], "AllocSize"));
        const char *tag = row_get(res, &res->rows[r], "Tag");
        safe_copy(p->tag,  sizeof(p->tag),  tag);
        safe_copy(p->type, sizeof(p->type),
                  row_get(res, &res->rows[r], "PoolType"));

        /* Heuristic: mark as suspicious if tag not in known list */
        p->suspicious = true;
        for (int t = 0; known_tags[t]; t++) {
            if (strncmp(p->tag, known_tags[t], 4) == 0) {
                p->suspicious = false;
                break;
            }
        }
    }

    kd->big_pools      = pools;
    kd->big_pool_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_memory_map  (windows.memmap.Memmap)                */
/* ------------------------------------------------------------------ */
int windows_collect_memory_map(const char *image_path, WinKernelData *kd)
{
    kd->memory_map       = NULL;
    kd->memory_map_count = 0;

    /* Use PID 0 (System) to get kernel memory map */
    const char *args[] = {"pid=0", NULL};
    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.memmap.Memmap", args);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.memmap] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    MemRegionRecord *regions = calloc(res->row_count + 1,
                                      sizeof(MemRegionRecord));
    if (!regions) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        MemRegionRecord *reg = &regions[r];
        reg->start = parse_u64(row_get(res, &res->rows[r], "Virtual"));
        reg->size  = parse_u64(row_get(res, &res->rows[r], "Size"));
        reg->end   = reg->start + reg->size;
        safe_copy(reg->name, sizeof(reg->name),
                  row_get(res, &res->rows[r], "Mapped File"));
        reg->pid   = parse_u64(row_get(res, &res->rows[r], "PID"));
    }

    kd->memory_map       = regions;
    kd->memory_map_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_statistics  (windows.statistics.Statistics)        */
/* ------------------------------------------------------------------ */
int windows_collect_statistics(const char *image_path, WinKernelData *kd)
{
    kd->statistics       = NULL;
    kd->statistics_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.statistics.Statistics", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.statistics] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    KVRecord *recs = calloc(res->row_count + 1, sizeof(KVRecord));
    if (!recs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        safe_copy(recs[r].key,   sizeof(recs[r].key),
                  row_get(res, &res->rows[r], "Stat"));
        safe_copy(recs[r].value, sizeof(recs[r].value),
                  row_get(res, &res->rows[r], "Count"));
        safe_copy(recs[r].extra, sizeof(recs[r].extra),
                  row_get(res, &res->rows[r], "Size"));
    }

    kd->statistics       = recs;
    kd->statistics_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_virtual_map  (windows.virtmap.VirtMap)             */
/* ------------------------------------------------------------------ */
int windows_collect_virtual_map(const char *image_path, WinKernelData *kd)
{
    kd->virtual_map       = NULL;
    kd->virtual_map_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.virtmap.VirtMap", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.virtmap] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    MemRegionRecord *regions = calloc(res->row_count + 1,
                                      sizeof(MemRegionRecord));
    if (!regions) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        MemRegionRecord *reg = &regions[r];
        reg->start = parse_u64(row_get(res, &res->rows[r], "Start"));
        reg->end   = parse_u64(row_get(res, &res->rows[r], "End"));
        reg->size  = (reg->end > reg->start) ? (reg->end - reg->start) : 0;
        safe_copy(reg->name, sizeof(reg->name),
                  row_get(res, &res->rows[r], "Name"));
    }

    kd->virtual_map       = regions;
    kd->virtual_map_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_module_dumps  (windows.modules.Modules --dump)     */
/* ------------------------------------------------------------------ */
int windows_collect_module_dumps(const char *image_path,
                                  WinKernelData *kd,
                                  const char *dump_dir)
{
    kd->module_dumps      = NULL;
    kd->module_dump_count = 0;

    /* Build extra args: dump=True and optional dump_dir */
    char dir_arg[4200] = "";
    const char *args[4] = {NULL, NULL, NULL, NULL};
    int ai = 0;
    args[ai++] = "dump=True";
    if (dump_dir && *dump_dir) {
        snprintf(dir_arg, sizeof(dir_arg), "dump_dir=%s", dump_dir);
        args[ai++] = dir_arg;
    }

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.modules.Modules", args);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.modules --dump] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    ModuleDumpRecord *dumps = calloc(res->row_count + 1,
                                     sizeof(ModuleDumpRecord));
    if (!dumps) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        ModuleDumpRecord *d = &dumps[r];
        safe_copy(d->name, sizeof(d->name),
                  row_get(res, &res->rows[r], "Name"));
        d->base = parse_u64(row_get(res, &res->rows[r], "Base"));
        d->size = parse_u64(row_get(res, &res->rows[r], "Size"));
        safe_copy(d->path, sizeof(d->path),
                  row_get(res, &res->rows[r], "Path"));
        /* Dump path returned by volatility3 in the "Dump" or "File output" column */
        const char *dp = row_get(res, &res->rows[r], "Dump");
        if (!dp || strcmp(dp, "N/A") == 0)
            dp = row_get(res, &res->rows[r], "File output");
        safe_copy(d->dump_path, sizeof(d->dump_path), dp);
        d->dump_ok = (d->dump_path[0] != '\0' &&
                      strcmp(d->dump_path, "N/A") != 0);
    }

    kd->module_dumps      = dumps;
    kd->module_dump_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_driver_irps  (windows.driverirp.DriverIrp)         */
/* ------------------------------------------------------------------ */

/* IRP major function index -> name mapping */
static const char *irp_name_table[] = {
    "IRP_MJ_CREATE",                 /* 0x00 */
    "IRP_MJ_CREATE_NAMED_PIPE",      /* 0x01 */
    "IRP_MJ_CLOSE",                  /* 0x02 */
    "IRP_MJ_READ",                   /* 0x03 */
    "IRP_MJ_WRITE",                  /* 0x04 */
    "IRP_MJ_QUERY_INFORMATION",      /* 0x05 */
    "IRP_MJ_SET_INFORMATION",        /* 0x06 */
    "IRP_MJ_QUERY_EA",               /* 0x07 */
    "IRP_MJ_SET_EA",                 /* 0x08 */
    "IRP_MJ_FLUSH_BUFFERS",          /* 0x09 */
    "IRP_MJ_QUERY_VOLUME_INFORMATION",/* 0x0A */
    "IRP_MJ_SET_VOLUME_INFORMATION", /* 0x0B */
    "IRP_MJ_DIRECTORY_CONTROL",      /* 0x0C */
    "IRP_MJ_FILE_SYSTEM_CONTROL",    /* 0x0D */
    "IRP_MJ_DEVICE_CONTROL",         /* 0x0E */
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",/* 0x0F */
    "IRP_MJ_SHUTDOWN",               /* 0x10 */
    "IRP_MJ_LOCK_CONTROL",           /* 0x11 */
    "IRP_MJ_CLEANUP",                /* 0x12 */
    "IRP_MJ_CREATE_MAILSLOT",        /* 0x13 */
    "IRP_MJ_QUERY_SECURITY",         /* 0x14 */
    "IRP_MJ_SET_SECURITY",           /* 0x15 */
    "IRP_MJ_POWER",                  /* 0x16 */
    "IRP_MJ_SYSTEM_CONTROL",         /* 0x17 */
    "IRP_MJ_DEVICE_CHANGE",          /* 0x18 */
    "IRP_MJ_QUERY_QUOTA",            /* 0x19 */
    "IRP_MJ_SET_QUOTA",              /* 0x1A */
    "IRP_MJ_PNP",                    /* 0x1B */
};
#define IRP_TABLE_SIZE ((int)(sizeof(irp_name_table)/sizeof(irp_name_table[0])))

int windows_collect_driver_irps(const char *image_path, WinKernelData *kd)
{
    kd->driver_irps      = NULL;
    kd->driver_irp_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.driverirp.DriverIrp", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.driverirp] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    IrpRecord *irps = calloc(res->row_count + 1, sizeof(IrpRecord));
    if (!irps) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        IrpRecord *irp = &irps[r];

        safe_copy(irp->driver_name, sizeof(irp->driver_name),
                  row_get(res, &res->rows[r], "Driver Name"));
        safe_copy(irp->driver_path, sizeof(irp->driver_path),
                  row_get(res, &res->rows[r], "Driver Path"));

        /* IRP index */
        const char *idx_str = row_get(res, &res->rows[r], "IRP");
        irp->irp_index = (uint32_t)parse_u64(idx_str);

        /* Resolve IRP name from index */
        if (irp->irp_index < (uint32_t)IRP_TABLE_SIZE)
            safe_copy(irp->irp_name, sizeof(irp->irp_name),
                      irp_name_table[irp->irp_index]);
        else
            snprintf(irp->irp_name, sizeof(irp->irp_name),
                     "IRP_MJ_0x%02X", irp->irp_index);

        irp->handler_addr = parse_u64(
            row_get(res, &res->rows[r], "Address"));
        safe_copy(irp->handler_module, sizeof(irp->handler_module),
                  row_get(res, &res->rows[r], "Module"));

        /* Hooked: volatility3 marks it in the "Hooked" or "Symbol" column */
        const char *hooked_col = row_get(res, &res->rows[r], "Hooked");
        irp->hooked = (strcmp(hooked_col, "True") == 0 ||
                       strcmp(hooked_col, "true") == 0 ||
                       strcmp(hooked_col, "1") == 0);
    }

    kd->driver_irps      = irps;
    kd->driver_irp_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_unloaded_modules                                    */
/*  (windows.unloadedmodules.UnloadedModules)                           */
/* ------------------------------------------------------------------ */
int windows_collect_unloaded_modules(const char *image_path, WinKernelData *kd)
{
    kd->unloaded_modules      = NULL;
    kd->unloaded_module_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.unloadedmodules.UnloadedModules", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.unloadedmodules] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    UnloadedModuleRecord *mods = calloc(res->row_count + 1,
                                        sizeof(UnloadedModuleRecord));
    if (!mods) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        UnloadedModuleRecord *m = &mods[r];
        safe_copy(m->name, sizeof(m->name),
                  row_get(res, &res->rows[r], "Name"));
        m->start_addr = parse_u64(row_get(res, &res->rows[r], "StartAddress"));
        m->end_addr   = parse_u64(row_get(res, &res->rows[r], "EndAddress"));
        safe_copy(m->unload_time, sizeof(m->unload_time),
                  row_get(res, &res->rows[r], "Time"));
    }

    kd->unloaded_modules      = mods;
    kd->unloaded_module_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_callbacks  (windows.callbacks.Callbacks)           */
/* ------------------------------------------------------------------ */
int windows_collect_callbacks(const char *image_path, WinKernelData *kd)
{
    kd->callbacks      = NULL;
    kd->callback_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.callbacks.Callbacks", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.callbacks] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    CallbackRecord *cbs = calloc(res->row_count + 1, sizeof(CallbackRecord));
    if (!cbs) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        CallbackRecord *cb = &cbs[r];

        safe_copy(cb->callback_type, sizeof(cb->callback_type),
                  row_get(res, &res->rows[r], "Type"));
        cb->callback_addr = parse_u64(
            row_get(res, &res->rows[r], "Callback"));
        safe_copy(cb->module, sizeof(cb->module),
                  row_get(res, &res->rows[r], "Module"));
        safe_copy(cb->symbol, sizeof(cb->symbol),
                  row_get(res, &res->rows[r], "Symbol"));
        /* Detail: combine component + detail columns if present */
        const char *component = row_get(res, &res->rows[r], "Component");
        const char *detail    = row_get(res, &res->rows[r], "Detail");
        if (strcmp(component, "N/A") != 0 && strcmp(detail, "N/A") != 0)
            snprintf(cb->detail, sizeof(cb->detail),
                     "%s: %s", component, detail);
        else if (strcmp(component, "N/A") != 0)
            safe_copy(cb->detail, sizeof(cb->detail), component);
        else
            safe_copy(cb->detail, sizeof(cb->detail), detail);
    }

    kd->callbacks      = cbs;
    kd->callback_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_timers  (windows.timers.Timers)                    */
/* ------------------------------------------------------------------ */
int windows_collect_timers(const char *image_path, WinKernelData *kd)
{
    kd->timers      = NULL;
    kd->timer_count = 0;

    PluginResult *res = pybridge_run_plugin(
        image_path, "windows.timers.Timers", NULL);
    if (!res || res->error) {
        if (res) {
            fprintf(stderr, "[windows.timers] %s\n", res->error);
            pybridge_free_result(res);
        }
        return -1;
    }

    TimerRecord *timers = calloc(res->row_count + 1, sizeof(TimerRecord));
    if (!timers) { pybridge_free_result(res); return -1; }

    for (int r = 0; r < res->row_count; r++) {
        TimerRecord *t = &timers[r];

        t->offset       = parse_u64(row_get(res, &res->rows[r], "Offset"));
        t->due_time     = parse_u64(row_get(res, &res->rows[r], "DueTime"));
        t->period       = parse_u64(row_get(res, &res->rows[r], "Period"));
        t->signaled     = parse_u64(row_get(res, &res->rows[r], "Signaled"));
        t->routine_addr = parse_u64(row_get(res, &res->rows[r], "Routine"));
        safe_copy(t->routine_module, sizeof(t->routine_module),
                  row_get(res, &res->rows[r], "Module"));
        safe_copy(t->routine_symbol, sizeof(t->routine_symbol),
                  row_get(res, &res->rows[r], "Symbol"));
    }

    kd->timers      = timers;
    kd->timer_count = res->row_count;
    pybridge_free_result(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  windows_collect_kernel_data  (aggregates all 11 above)             */
/* ------------------------------------------------------------------ */
int windows_collect_kernel_data(const char *image_path, WinKernelData *kd)
{
    memset(kd, 0, sizeof(*kd));

    windows_collect_os_info(image_path, kd);
    windows_collect_loaded_modules(image_path, kd);
    windows_collect_module_dumps(image_path, kd, NULL);  /* NULL = default dir */
    windows_collect_driver_irps(image_path, kd);
    windows_collect_unloaded_modules(image_path, kd);
    windows_collect_callbacks(image_path, kd);
    windows_collect_timers(image_path, kd);
    windows_collect_big_pools(image_path, kd);
    windows_collect_memory_map(image_path, kd);
    windows_collect_statistics(image_path, kd);
    windows_collect_virtual_map(image_path, kd);

    return 0;
}
