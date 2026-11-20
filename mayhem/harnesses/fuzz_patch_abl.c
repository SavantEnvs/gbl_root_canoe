// libFuzzer harness for the ABL patcher: the same entry point patch_abl's main()
// uses (PatchBuffer on the whole LinuxLoader.efi image, patched in place).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "patchs/core.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    // PatchBuffer logs every step to stdout; silence it (not per-input state).
    if (!freopen("/dev/null", "w", stdout)) {}
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // patch_abl's read_file() stores the file size in an int32_t.
    if (size > INT32_MAX) return -1;
    // Exact-size heap copy (as read_file does) so ASan sees out-of-bounds accesses.
    char *buf = (char *)malloc(size ? size : 1);
    if (!buf) return 0;
    if (size) memcpy(buf, data, size);
    PatchBuffer(buf, (int32_t)size);
    free(buf);
    return 0;
}
