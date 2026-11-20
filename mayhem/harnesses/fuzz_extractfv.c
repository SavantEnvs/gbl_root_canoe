// libFuzzer harness for extractfv (ABL ELF/FV/LZMA -> PE/BMP extractor). Drives the
// tool's own main() — renamed via -Dmain=extractfv_main — on the fuzz input written to a
// scratch file, in "-e all" mode so every PE/BMP extraction path runs.
#define main extractfv_main
#include "../../submodules/ablfvextractor/extractfv.c"
#undef main

#include <dirent.h>
#include <unistd.h>

static char g_dir[4096];
static char g_in[4096 + 16];
static char g_out[4096 + 16];

static void clean_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    char p[8192];
    while ((ent = readdir(d)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        snprintf(p, sizeof(p), "%s/%s", dir, ent->d_name);
        unlink(p);
    }
    closedir(d);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    snprintf(g_dir, sizeof(g_dir), "%s/extractfv-XXXXXX", tmp);
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); abort(); }
    snprintf(g_in, sizeof(g_in), "%s/in.img", g_dir);
    snprintf(g_out, sizeof(g_out), "%s/out", g_dir);
    if (!freopen("/dev/null", "w", stdout)) {}
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FILE *f = fopen(g_in, "wb");
    if (!f) abort();
    if (size && fwrite(data, 1, size, f) != size) abort();
    fclose(f);

    char a0[] = "extractfv", a1[] = "-v", a2[] = "-e", a3[] = "all", a4[] = "-o";
    char *args[] = {a0, a1, a2, a3, a4, g_out, g_in, NULL};
    optind = 0;  // full getopt reset (glibc) between calls
    extractfv_main(7, args);

    clean_dir(g_out);
    unlink(g_in);
    return 0;
}
