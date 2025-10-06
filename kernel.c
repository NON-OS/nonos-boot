// // kernel.c
// #include <stdint.h>
// #include <stddef.h>

// /* ===== serial (COM1) ===== */
// static inline void outb(uint16_t p, uint8_t v){ __asm__ __volatile__("outb %0,%1"::"a"(v),"Nd"(p)); }
// static inline uint8_t inb(uint16_t p){ uint8_t r; __asm__ __volatile__("inb %1,%0":"=a"(r):"Nd"(p)); return r; }
// #define COM1 0x3F8
// static void serial_init(void){
//   outb(COM1+1,0); outb(COM1+3,0x80); outb(COM1+0,0x03); outb(COM1+1,0x00);
//   outb(COM1+3,0x03); outb(COM1+2,0xC7); outb(COM1+4,0x0B);
// }
// static int tx_ready(void){ return inb(COM1+5) & 0x20; }
// static void putc(char c){ while(!tx_ready()){} outb(COM1,c); }
// static void puts(const char*s){ for(;*s;++s){ if(*s=='\n') putc('\r'); putc(*s);} }
// static void hex8(uint8_t v){ const char*h="0123456789ABCDEF"; putc(h[v>>4]); putc(h[v&15]); }
// static void hex64(uint64_t v){ for(int i=60;i>=0;i-=8) hex8((v>>i)&0xFF); }

// /* UEFI memdesc field offsets for x86_64 (Rev 1): */
// #define OFF_TYPE        0   // u32
// #define OFF_PHYS_START  8   // u64
// #define OFF_NUM_PAGES   24  // u64
// #define OFF_ATTR        32  // u64

// /* kernel entry: pointer + length + descriptor size */
// void kernel_main(const void* mmap_ptr, size_t mmap_len, size_t desc_size) {
//   serial_init();
//   puts("=== UEFI Memory Map ===\n");

//   if(!mmap_ptr || mmap_len==0 || desc_size==0){ puts("empty\n"); for(;;)__asm__ __volatile__("hlt"); }

//   const uint8_t* p = (const uint8_t*)mmap_ptr;
//   size_t count = mmap_len / desc_size;

//   for(size_t i=0;i<count;i++){
//     const uint8_t* ent = p + i*desc_size;
//     uint32_t typ       = *(const uint32_t*)(ent + OFF_TYPE);
//     uint64_t phys      = *(const uint64_t*)(ent + OFF_PHYS_START);
//     uint64_t pages     = *(const uint64_t*)(ent + OFF_NUM_PAGES);
//     uint64_t attr      = *(const uint64_t*)(ent + OFF_ATTR);

//     puts("Type="); hex64(typ);
//     puts(" PA=");  hex64(phys);
//     puts(" Pages="); hex64(pages);
//     puts(" Attr=");  hex64(attr);
//     puts("\n");
//   }

//   for(;;) __asm__ __volatile__("hlt");
// }
