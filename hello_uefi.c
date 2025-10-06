#include <stdint.h>

typedef uint16_t CHAR16;
typedef void* EFI_HANDLE;
typedef uint64_t EFI_STATUS;

typedef struct {
  uint64_t Signature;
  uint32_t Revision;
  uint32_t HeaderSize;
  uint32_t CRC32;
  uint32_t Reserved;
} EFI_TABLE_HEADER;

typedef struct SIMPLE_TEXT_OUTPUT_INTERFACE SIMPLE_TEXT_OUTPUT_INTERFACE;
struct SIMPLE_TEXT_OUTPUT_INTERFACE {
  void* _Reset;
  EFI_STATUS (*OutputString)(SIMPLE_TEXT_OUTPUT_INTERFACE* This, const CHAR16* String);
  // (we ignore the rest of the methods—unused)
};

typedef struct {
  EFI_TABLE_HEADER              Hdr;
  void*                         FirmwareVendor;   // unused
  uint32_t                      FirmwareRevision; // unused
  void*                         ConsoleInHandle;  // unused
  void*                         ConIn;            // unused
  EFI_HANDLE                    ConsoleOutHandle; // unused
  SIMPLE_TEXT_OUTPUT_INTERFACE* ConOut;           // we use this
  // ... we ignore the rest of the fields
} EFI_SYSTEM_TABLE;

/* EFI entry point (Microsoft x64 calling convention is default on -target windows) */
EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable) {
  static const CHAR16 msg[] = u"hello from UEFI\r\n";
  SystemTable->ConOut->OutputString(SystemTable->ConOut, msg);
  // loop so the window stays up if firmware would immediately exit
  for(;;) { __asm__ __volatile__("" ::: "memory"); }
  return 0;
}
