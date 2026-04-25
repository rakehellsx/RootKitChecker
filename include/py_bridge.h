/**
 * py_bridge.h - Python/C bridge for volatility3 invocation
 *
 * Provides helpers to:
 *  - initialize / finalize the embedded Python interpreter
 *  - run a named volatility3 plugin and collect its TreeGrid rows
 *  - convert Python objects to C strings safely
 */

#ifndef PY_BRIDGE_H
#define PY_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/* Maximum columns returned per row */
#define MAX_COLUMNS 64

/* A single row from a volatility3 TreeGrid result */
typedef struct {
    char  *columns[MAX_COLUMNS];  /* heap-allocated strings; NULL = absent */
    int    col_count;
    int    depth;                 /* nesting depth in tree (0 = root)       */
} PluginRow;

/* Result set from running one plugin */
typedef struct {
    char      **col_names;        /* column header names                    */
    int         col_count;
    PluginRow  *rows;
    int         row_count;
    char       *error;            /* NULL if no error                       */
} PluginResult;

/**
 * Initialize the embedded Python interpreter.
 * @param venv_path  Path to a virtualenv directory (may be NULL).
 * @return 0 on success.
 */
int  pybridge_init(const char *venv_path);

/**
 * Finalize the embedded Python interpreter.
 */
void pybridge_fini(void);

/**
 * Run a volatility3 plugin and return its rows.
 *
 * @param image_path   Path to the memory image file.
 * @param plugin_name  Dotted plugin name, e.g. "windows.pslist.PsList".
 * @param extra_args   NULL-terminated array of extra "key=value" strings,
 *                     or NULL for no extras.
 * @return  Heap-allocated PluginResult; free with pybridge_free_result().
 *          On fatal error returns NULL.
 */
PluginResult *pybridge_run_plugin(const char *image_path,
                                  const char *plugin_name,
                                  const char **extra_args);

/**
 * Free a PluginResult returned by pybridge_run_plugin().
 */
void pybridge_free_result(PluginResult *res);

/**
 * Set the Volatility3 symbol table path.
 *
 * This path is forwarded to vol_runner.py via the --symbols argument and
 * also exported as the VOLATILITY_SYMBOLS environment variable so that
 * Volatility3's automagic layer can locate ISF files automatically.
 *
 * @param symbols_path  Directory containing symbol JSON/XZ files, or path
 *                      to a single ISF .json file.  Pass NULL to clear.
 */
void pybridge_set_symbols_path(const char *symbols_path);

/**
 * Detect the OS of a memory image by probing windows.info / linux.pslist.
 * Returns "windows", "linux", "macos", or "unknown".
 */
const char *pybridge_detect_os(const char *image_path);

#ifdef __cplusplus
}
#endif

#endif /* PY_BRIDGE_H */
