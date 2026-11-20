// Host implementations of the EDK2 BaseLib / BaseMemoryLib / MemoryAllocationLib functions that
// SuperFbEntryList.c and SfbPeVerify.c call, with EDK2's semantics (CHAR16 strings, Length in bytes). Mocks the
// firmware library environment only; no project code is replaced.
#include <stdlib.h>
#include <string.h>
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

VOID *EFIAPI CopyMem(OUT VOID *Destination, IN CONST VOID *Source, IN UINTN Length) {
    return memmove(Destination, Source, Length);
}
VOID *EFIAPI ZeroMem(OUT VOID *Buffer, IN UINTN Length) { return memset(Buffer, 0, Length); }
VOID EFIAPI FreePool(IN VOID *Buffer) { free(Buffer); }
UINTN EFIAPI __StrLen(IN CONST CHAR16 *String) {
    UINTN n = 0;
    while (String[n] != 0) n++;
    return n;
}
INTN EFIAPI StrCmp(IN CONST CHAR16 *FirstString, IN CONST CHAR16 *SecondString) {
    while (*FirstString != 0 && *FirstString == *SecondString) { FirstString++; SecondString++; }
    return (INTN)*FirstString - (INTN)*SecondString;
}
INTN EFIAPI StrnCmp(IN CONST CHAR16 *FirstString, IN CONST CHAR16 *SecondString, IN UINTN Length) {
    if (Length == 0) return 0;
    while (*FirstString != 0 && *FirstString == *SecondString && Length > 1) {
        FirstString++; SecondString++; Length--;
    }
    return (INTN)*FirstString - (INTN)*SecondString;
}
// Unaligned little-endian loads, byte by byte (the typed pointer may be misaligned by design).
UINT16 EFIAPI ReadUnaligned16(IN CONST UINT16 *Buffer) {
    CONST UINT8 *b = (CONST UINT8 *)(CONST VOID *)Buffer;
    return (UINT16)(b[0] | (b[1] << 8));
}
UINT32 EFIAPI ReadUnaligned32(IN CONST UINT32 *Buffer) {
    CONST UINT8 *b = (CONST UINT8 *)(CONST VOID *)Buffer;
    return (UINT32)b[0] | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) | ((UINT32)b[3] << 24);
}
