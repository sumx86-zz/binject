#ifndef BINJECT_HH
#define BINJECT_HH 1

#ifdef __cplusplus
extern "C" {
#endif

char errbuf[0xff];

typedef struct
{
    unsigned char *c;
    size_t size;
}
bytecode_t;

#ifdef BINJECT32
    typedef Elf32_Addr Belf_Addr;
    typedef Elf32_Ehdr Belf_Ehdr;
    typedef Elf32_Shdr Belf_Shdr;
    typedef Elf32_Phdr Belf_Phdr;
    typedef Elf32_Off  Belf_Off;
#endif

#ifdef BINJECT64
    typedef Elf64_Addr Belf_Addr;
    typedef Elf64_Ehdr Belf_Ehdr;
    typedef Elf64_Shdr Belf_Shdr;
    typedef Elf64_Phdr Belf_Phdr;
    typedef Elf64_Off  Belf_Off;
#endif

typedef struct
{
    int fd;
    int psize;           // page size
    char *buff;          // file buffer
    const char *fname;   // file name
    size_t size;         // file size
    size_t newsize;      // file size + psize (page size)
    Belf_Ehdr *header;  // elf header
    Belf_Shdr *shdr;    // elf Section Headers Table
    Belf_Phdr *phdr;    // elf Program Headers
    bool closed = false;

    void close_fd( void ) {
        if ( close( this->fd ) == 0x00 ) {
            this->closed = true;
        }
    }
}
ELF_t;

const char *elf_err[0x07] = {
    "File is not an executable!",
    "File is not ELF format!",
    "Invalid shellcode format!",
    "\nFile architecture is not x86!",
    "\nFile architecture is not x86-64!",
    "Invalid shellcode format!"
};

enum {
    ELFTYPE    = -1,
    ELFORMAT   = -2,
    SHLCFORMAT = -3,
    ELFB32     = -4,
    ELFB64     = -5,
    ELFXDIGIT  = -6
};

#ifdef __cplusplus
}
#endif

#endif
