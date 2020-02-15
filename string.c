#include <string.h>

int chcount( const char *str, const char ch )
{
    if ( str == NULL || strlen( str ) <= 0 )
        return 0;

    int c = 0;
    while ( *str != '\x00' ) {
        if ( *str++ == ch ) c++;
    }
    return c;
}