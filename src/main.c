/**
 * main.c  –  memscope: Volatility3-based memory forensics tool
 *
 * Usage:
 *   memscope -i <image_path> [-o <output_file>] [-v <venv_path>]
 *            [--os windows|linux|auto] [--pretty] [--no-net]
 *            [--no-modules] [--no-hooks]
 *
 * Options:
 *   -i <path>        Memory image file path (required)
 *   -o <path>        Output JSON file (default: stdout)
 *   -v <path>        Python virtualenv directory
 *   --os <type>      Force OS type: windows, linux, auto (default: auto)
 *   --pretty         Pretty-print JSON output
 *   --no-net         Skip network connection analysis
 *   --no-modules     Skip kernel module analysis
 *   --no-hooks       Skip hook / rootkit detection
 *   --version        Print version and exit
 *   -h, --help       Show this help
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "memscope.h"
#include "py_bridge.h"
#include "windows_scan.h"
#include "linux_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

/* ------------------------------------------------------------------ */
/*  memscope_free_result                                                */
/* ------------------------------------------------------------------ */
void memscope_free_result(ScanResult *result)
{
    if (!result) return;
    free(result->processes);
    free(result->hidden_processes);
    free(result->inactive_processes);
    free(result->connections);
    free(result->hidden_connections);
    free(result->modules);
    free(result->hidden_modules);
    free(result->hooks);
    for (int i = 0; i < result->error_count; i++) free(result->errors[i]);
    free(result->errors);
    memset(result, 0, sizeof(*result));
}

/* ------------------------------------------------------------------ */
/*  memscope_init / memscope_fini                                       */
/* ------------------------------------------------------------------ */
int memscope_init(const char *venv_path)
{
    return pybridge_init(venv_path);
}

void memscope_fini(void)
{
    pybridge_fini();
}

/* ------------------------------------------------------------------ */
/*  memscope_detect_os                                                  */
/* ------------------------------------------------------------------ */
OsType memscope_detect_os(const char *image_path)
{
    const char *os = pybridge_detect_os(image_path);
    if (strcmp(os, "windows") == 0) return OS_WINDOWS;
    if (strcmp(os, "linux")   == 0) return OS_LINUX;
    if (strcmp(os, "macos")   == 0) return OS_MACOS;
    return OS_UNKNOWN;
}

/* ------------------------------------------------------------------ */
/*  memscope_scan                                                       */
/* ------------------------------------------------------------------ */
int memscope_scan(const char *image_path, ScanResult *result)
{
    memset(result, 0, sizeof(*result));

    /* Record scan time */
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(result->scan_time, sizeof(result->scan_time),
             "%Y-%m-%dT%H:%M:%SZ", tm_info);

    strncpy(result->image_path, image_path,
            sizeof(result->image_path) - 1);

    OsType os = memscope_detect_os(image_path);
    if (os == OS_WINDOWS) {
        return windows_full_scan(image_path, result);
    } else if (os == OS_LINUX) {
        return linux_full_scan(image_path, result);
    } else {
        fprintf(stderr,
                "[memscope] Could not detect OS type. "
                "Trying Windows first...\n");
        int rc = windows_full_scan(image_path, result);
        if (rc != 0 || result->process_count == 0) {
            memscope_free_result(result);
            memset(result, 0, sizeof(*result));
            strncpy(result->image_path, image_path,
                    sizeof(result->image_path) - 1);
            strftime(result->scan_time, sizeof(result->scan_time),
                     "%Y-%m-%dT%H:%M:%SZ", tm_info);
            fprintf(stderr, "[memscope] Trying Linux...\n");
            return linux_full_scan(image_path, result);
        }
        return rc;
    }
}

/* ------------------------------------------------------------------ */
/*  CLI option flags                                                    */
/* ------------------------------------------------------------------ */
typedef struct {
    char   image_path[2048];
    char   output_path[2048];
    char   venv_path[2048];
    char   os_override[16];   /* "windows", "linux", "auto" */
    bool   pretty;
    bool   skip_net;
    bool   skip_modules;
    bool   skip_hooks;
} CliOptions;

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <image_path> [options]\n"
        "\n"
        "Options:\n"
        "  -i <path>        Memory image file path (required)\n"
        "  -o <path>        Output JSON file (default: stdout)\n"
        "  -v <path>        Python virtualenv directory\n"
        "  --os <type>      Force OS: windows | linux | auto (default: auto)\n"
        "  --pretty         Pretty-print JSON\n"
        "  --no-net         Skip network analysis\n"
        "  --no-modules     Skip module analysis\n"
        "  --no-hooks       Skip hook/rootkit detection\n"
        "  --version        Print version and exit\n"
        "  -h, --help       Show this help\n"
        "\n"
        "Examples:\n"
        "  %s -i /mnt/images/win10.vmem --pretty\n"
        "  %s -i /mnt/images/linux.lime -o report.json --os linux\n"
        "  %s -i dump.raw -v /opt/vol3-venv --pretty -o out.json\n",
        prog, prog, prog, prog);
}

static int parse_args(int argc, char *argv[], CliOptions *opts)
{
    memset(opts, 0, sizeof(*opts));
    strncpy(opts->os_override, "auto", sizeof(opts->os_override) - 1);

    static struct option long_opts[] = {
        {"os",          required_argument, 0, 0},
        {"pretty",      no_argument,       0, 1},
        {"no-net",      no_argument,       0, 2},
        {"no-modules",  no_argument,       0, 3},
        {"no-hooks",    no_argument,       0, 4},
        {"version",     no_argument,       0, 5},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c, idx = 0;
    while ((c = getopt_long(argc, argv, "i:o:v:h", long_opts, &idx)) != -1) {
        switch (c) {
        case 'i':
            strncpy(opts->image_path, optarg,
                    sizeof(opts->image_path) - 1);
            break;
        case 'o':
            strncpy(opts->output_path, optarg,
                    sizeof(opts->output_path) - 1);
            break;
        case 'v':
            strncpy(opts->venv_path, optarg,
                    sizeof(opts->venv_path) - 1);
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        case 0:
            strncpy(opts->os_override, optarg,
                    sizeof(opts->os_override) - 1);
            break;
        case 1: opts->pretty       = true; break;
        case 2: opts->skip_net     = true; break;
        case 3: opts->skip_modules = true; break;
        case 4: opts->skip_hooks   = true; break;
        case 5:
            printf("memscope version %s\n", MEMSCOPE_VERSION_STR);
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (strlen(opts->image_path) == 0) {
        fprintf(stderr, "Error: -i <image_path> is required.\n\n");
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    CliOptions opts;
    if (parse_args(argc, argv, &opts) != 0)
        return 1;

    /* Determine venv path */
    const char *venv = strlen(opts.venv_path) > 0
                       ? opts.venv_path : NULL;

    /* Check for MEMSCOPE_VENV environment variable as fallback */
    if (!venv) {
        const char *env_venv = getenv("MEMSCOPE_VENV");
        if (env_venv && strlen(env_venv) > 0)
            venv = env_venv;
    }

    fprintf(stderr, "[memscope] Initializing (venv: %s)...\n",
            venv ? venv : "system Python");

    if (memscope_init(venv) != 0) {
        fprintf(stderr, "[memscope] Initialization failed.\n");
        return 1;
    }

    fprintf(stderr, "[memscope] Scanning image: %s\n", opts.image_path);

    ScanResult result;

    /* OS override */
    int rc = 0;
    if (strcmp(opts.os_override, "windows") == 0) {
        memset(&result, 0, sizeof(result));
        time_t now = time(NULL);
        struct tm *tm_info = gmtime(&now);
        strftime(result.scan_time, sizeof(result.scan_time),
                 "%Y-%m-%dT%H:%M:%SZ", tm_info);
        strncpy(result.image_path, opts.image_path,
                sizeof(result.image_path) - 1);
        rc = windows_full_scan(opts.image_path, &result);
    } else if (strcmp(opts.os_override, "linux") == 0) {
        memset(&result, 0, sizeof(result));
        time_t now = time(NULL);
        struct tm *tm_info = gmtime(&now);
        strftime(result.scan_time, sizeof(result.scan_time),
                 "%Y-%m-%dT%H:%M:%SZ", tm_info);
        strncpy(result.image_path, opts.image_path,
                sizeof(result.image_path) - 1);
        rc = linux_full_scan(opts.image_path, &result);
    } else {
        rc = memscope_scan(opts.image_path, &result);
    }

    if (rc != 0) {
        fprintf(stderr, "[memscope] Scan returned error code %d\n", rc);
        /* Continue to output whatever was collected */
    }

    fprintf(stderr,
            "[memscope] Scan complete. "
            "Processes: %d, Hidden: %d, Inactive: %d, "
            "Connections: %d, Hidden conns: %d, "
            "Modules: %d, Hidden mods: %d, Hooks: %d\n",
            result.process_count,
            result.hidden_process_count,
            result.inactive_process_count,
            result.connection_count,
            result.hidden_connection_count,
            result.module_count,
            result.hidden_module_count,
            result.hook_count);

    /* Serialize to JSON */
    cJSON *json = memscope_to_json(&result);
    if (!json) {
        fprintf(stderr, "[memscope] JSON serialization failed.\n");
        memscope_free_result(&result);
        memscope_fini();
        return 1;
    }

    char *json_str = opts.pretty
                     ? cJSON_Print(json)
                     : cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!json_str) {
        fprintf(stderr, "[memscope] JSON rendering failed.\n");
        memscope_free_result(&result);
        memscope_fini();
        return 1;
    }

    /* Output */
    if (strlen(opts.output_path) > 0) {
        FILE *fp = fopen(opts.output_path, "w");
        if (!fp) {
            perror("fopen output file");
            free(json_str);
            memscope_free_result(&result);
            memscope_fini();
            return 1;
        }
        fputs(json_str, fp);
        fputc('\n', fp);
        fclose(fp);
        fprintf(stderr, "[memscope] Output written to: %s\n",
                opts.output_path);
    } else {
        fputs(json_str, stdout);
        fputc('\n', stdout);
    }

    free(json_str);
    memscope_free_result(&result);
    memscope_fini();
    return 0;
}
