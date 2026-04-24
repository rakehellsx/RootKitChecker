/**
 * py_bridge.c  –  C wrapper that invokes vol_runner.py as a subprocess
 *                 and parses the JSON output using cJSON.
 *
 * Design rationale:
 *   Embedding CPython directly requires matching the exact interpreter
 *   version used by volatility3.  Using subprocess isolation avoids
 *   ABI mismatches and keeps the C binary independent of the Python
 *   installation, while still providing a clean C API to the rest of
 *   the tool.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "py_bridge.h"
#include "../../third_party/cjson/cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

/* ------------------------------------------------------------------ */
/*  Internal globals                                                    */
/* ------------------------------------------------------------------ */

static char g_python_exe[1024]  = "python3";
static char g_runner_script[2048] = "";
static bool g_initialized = false;

/* ------------------------------------------------------------------ */
/*  Helper: read all data from a file descriptor into a heap buffer    */
/* ------------------------------------------------------------------ */
static char *read_fd_all(int fd)
{
    size_t  cap  = 65536;
    size_t  used = 0;
    char   *buf  = malloc(cap);
    if (!buf) return NULL;

    ssize_t n;
    while ((n = read(fd, buf + used, cap - used - 1)) > 0) {
        used += (size_t)n;
        if (used + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }
    }
    buf[used] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Helper: run a command and capture stdout                           */
/* ------------------------------------------------------------------ */
static char *run_command(const char *const argv[])
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        /* child */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        /* redirect stderr to /dev/null to suppress volatility noise */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        close(pipefd[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    /* parent */
    close(pipefd[1]);
    char *output = read_fd_all(pipefd[0]);
    close(pipefd[0]);
    waitpid(pid, NULL, 0);
    return output;
}

/* ------------------------------------------------------------------ */
/*  pybridge_init                                                       */
/* ------------------------------------------------------------------ */
int pybridge_init(const char *venv_path)
{
    if (g_initialized) return 0;

    /* Determine Python executable */
    if (venv_path && *venv_path) {
        snprintf(g_python_exe, sizeof(g_python_exe),
                 "%s/bin/python", venv_path);
        /* verify it exists */
        if (access(g_python_exe, X_OK) != 0) {
            snprintf(g_python_exe, sizeof(g_python_exe),
                     "%s/bin/python3", venv_path);
        }
    } else {
        strncpy(g_python_exe, "python3", sizeof(g_python_exe) - 1);
    }

    /* Locate vol_runner.py relative to this binary's directory.
     * We use /proc/self/exe to find the binary, then look for
     * scripts/vol_runner.py in the project root.                     */
    char exe_path[2048] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        /* strip filename */
        char *slash = strrchr(exe_path, '/');
        if (slash) *slash = '\0';
        /* go up one level (from build/ to project root) */
        slash = strrchr(exe_path, '/');
        if (slash) *slash = '\0';
        snprintf(g_runner_script, sizeof(g_runner_script),
                 "%s/scripts/vol_runner.py", exe_path);
    }

    /* Fallback: look next to the binary */
    if (access(g_runner_script, R_OK) != 0) {
        snprintf(g_runner_script, sizeof(g_runner_script),
                 "scripts/vol_runner.py");
    }

    g_initialized = true;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  pybridge_fini                                                       */
/* ------------------------------------------------------------------ */
void pybridge_fini(void)
{
    g_initialized = false;
}

/* ------------------------------------------------------------------ */
/*  pybridge_detect_os                                                  */
/* ------------------------------------------------------------------ */
const char *pybridge_detect_os(const char *image_path)
{
    static char os_buf[32] = "unknown";

    const char *argv[] = {
        g_python_exe,
        g_runner_script,
        "--image", image_path,
        "--detect-os",
        NULL
    };

    char *output = run_command(argv);
    if (!output) return os_buf;

    cJSON *root = cJSON_Parse(output);
    free(output);
    if (!root) return os_buf;

    cJSON *os_item = cJSON_GetObjectItemCaseSensitive(root, "os");
    if (cJSON_IsString(os_item) && os_item->valuestring) {
        strncpy(os_buf, os_item->valuestring, sizeof(os_buf) - 1);
    }
    cJSON_Delete(root);
    return os_buf;
}

/* ------------------------------------------------------------------ */
/*  pybridge_run_plugin                                                 */
/* ------------------------------------------------------------------ */
PluginResult *pybridge_run_plugin(const char *image_path,
                                  const char *plugin_name,
                                  const char **extra_args)
{
    /* Build argv dynamically */
    const char *base_argv[] = {
        g_python_exe,
        g_runner_script,
        "--image", image_path,
        "--plugin", plugin_name,
        NULL
    };

    /* Count extra args */
    int extra_count = 0;
    if (extra_args) {
        while (extra_args[extra_count]) extra_count++;
    }

    /* Allocate argv array: base(6) + "--args" + extras + NULL */
    int total = 6 + (extra_count > 0 ? 1 + extra_count : 0) + 1;
    const char **argv = calloc(total, sizeof(char *));
    if (!argv) return NULL;

    int idx = 0;
    for (int i = 0; base_argv[i]; i++) argv[idx++] = base_argv[i];

    if (extra_count > 0) {
        argv[idx++] = "--args";
        for (int i = 0; i < extra_count; i++) argv[idx++] = extra_args[i];
    }
    argv[idx] = NULL;

    char *output = run_command(argv);
    free(argv);

    PluginResult *result = calloc(1, sizeof(PluginResult));
    if (!result) { free(output); return NULL; }

    if (!output) {
        result->error = strdup("Failed to run vol_runner.py");
        return result;
    }

    /* Parse JSON */
    cJSON *root = cJSON_Parse(output);
    free(output);

    if (!root) {
        result->error = strdup("Failed to parse JSON output from vol_runner.py");
        return result;
    }

    /* Check for error field */
    cJSON *err_item = cJSON_GetObjectItemCaseSensitive(root, "error");
    if (cJSON_IsString(err_item) && err_item->valuestring) {
        result->error = strdup(err_item->valuestring);
        cJSON_Delete(root);
        return result;
    }

    /* Parse columns */
    cJSON *cols_arr = cJSON_GetObjectItemCaseSensitive(root, "columns");
    if (cJSON_IsArray(cols_arr)) {
        result->col_count = cJSON_GetArraySize(cols_arr);
        result->col_names = calloc(result->col_count, sizeof(char *));
        for (int i = 0; i < result->col_count; i++) {
            cJSON *c = cJSON_GetArrayItem(cols_arr, i);
            result->col_names[i] = strdup(
                cJSON_IsString(c) ? c->valuestring : "");
        }
    }

    /* Parse rows */
    cJSON *rows_arr = cJSON_GetObjectItemCaseSensitive(root, "rows");
    if (cJSON_IsArray(rows_arr)) {
        result->row_count = cJSON_GetArraySize(rows_arr);
        result->rows = calloc(result->row_count, sizeof(PluginRow));

        for (int r = 0; r < result->row_count; r++) {
            cJSON *row_obj = cJSON_GetArrayItem(rows_arr, r);
            PluginRow *row = &result->rows[r];

            /* depth */
            cJSON *depth_item = cJSON_GetObjectItemCaseSensitive(
                row_obj, "__depth__");
            row->depth = cJSON_IsNumber(depth_item)
                         ? (int)depth_item->valuedouble : 0;

            /* columns */
            row->col_count = result->col_count;
            for (int c = 0; c < result->col_count && c < MAX_COLUMNS; c++) {
                cJSON *cell = cJSON_GetObjectItemCaseSensitive(
                    row_obj, result->col_names[c]);
                if (cJSON_IsNull(cell) || !cell) {
                    row->columns[c] = strdup("N/A");
                } else if (cJSON_IsString(cell)) {
                    row->columns[c] = strdup(cell->valuestring);
                } else if (cJSON_IsNumber(cell)) {
                    char nbuf[64];
                    snprintf(nbuf, sizeof(nbuf), "%lld",
                             (long long)cell->valuedouble);
                    row->columns[c] = strdup(nbuf);
                } else if (cJSON_IsBool(cell)) {
                    row->columns[c] = strdup(
                        cJSON_IsTrue(cell) ? "true" : "false");
                } else {
                    row->columns[c] = strdup("N/A");
                }
            }
        }
    }

    cJSON_Delete(root);
    return result;
}

/* ------------------------------------------------------------------ */
/*  pybridge_free_result                                                */
/* ------------------------------------------------------------------ */
void pybridge_free_result(PluginResult *res)
{
    if (!res) return;
    free(res->error);
    for (int i = 0; i < res->col_count; i++) free(res->col_names[i]);
    free(res->col_names);
    if (res->rows) {
        for (int r = 0; r < res->row_count; r++) {
            for (int c = 0; c < res->rows[r].col_count; c++)
                free(res->rows[r].columns[c]);
        }
        free(res->rows);
    }
    free(res);
}
