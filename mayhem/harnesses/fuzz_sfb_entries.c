// libFuzzer harness for the super-fastboot ENTRIES.CFG parser
// (submodules/uefi/edk2/QcomModulePkg/Application/LinuxLoader/SuperFbEntryList.c).
// On device, SfbLoadStoredEntries() reads up to SFB_ENTRIES_MAX_BYTES of ENTRIES.CFG into a
// zeroed buffer, NUL-terminates it, and SfbAppendEntryLines() runs NextLine -> ParseLine ->
// ListAppend over it; the menu then walks names (NameChild/NameHidden) and the store writes the list
// back with FormatLine. SuperFbEntryList.c "touches no firmware services, so it builds on the host";
// the few BaseLib/BaseMemoryLib/MemoryAllocationLib calls it makes are in sfb_host_stubs.c.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "SuperFbEntryList.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // The firmware reader never hands the parser more than SFB_ENTRIES_MAX_BYTES (SuperFbEntries.c).
    if (size > SFB_ENTRIES_MAX_BYTES) return -1;
    CHAR8 *text = (CHAR8 *)malloc(size + 1);
    if (!text) return 0;
    memcpy(text, data, size);
    text[size] = '\0';

    static SFB_ENTRY_LIST list;   // ~50 KB; zeroed per input below
    memset(&list, 0, sizeof(list));

    const CHAR8 *cursor = text;
    CHAR8 line[SFB_ENTRY_LINE_BYTES];
    SFB_BOOT_ENTRY entry;
    while (SfbEntryNextLine(&cursor, line, sizeof(line))) {
        memset(&entry, 0, sizeof(entry));
        if (!SfbEntryParseLine(line, &entry.Spec)) continue;
        SfbEntryListAppend(&list, &entry);
    }

    // What the menu and the store do with the stored list.
    CHAR8 out[SFB_ENTRY_LINE_BYTES];
    CHAR16 child[SFB_NAME_CHARS];
    BOOLEAN folder;
    static const CHAR16 root[] = {0};
    for (UINTN i = 0; i < list.Count; i++) {
        SFB_ENTRY_SPEC *spec = &list.Entry[i].Spec;
        if (SfbEntryFormatLine(spec, out, sizeof(out))) {
            SFB_ENTRY_SPEC again;
            SfbEntryParseLine(out, &again);
            SfbEntrySameTarget(spec, &again);
        }
        (void)SfbEntryNameHidden(spec->Name);
        if (SfbEntryNameChild(spec->Name, root, child, SFB_NAME_CHARS, &folder) && folder)
            (void)SfbEntryNameChild(spec->Name, child, child, SFB_NAME_CHARS, &folder);
    }
    if (list.Count > 1) {
        SfbEntryListMove(&list, 0, list.Count - 1);
        SfbEntryListRemove(&list, 0);
    }
    SfbEntryListFree(&list);
    free(text);
    return 0;
}
