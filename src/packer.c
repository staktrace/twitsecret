#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#define WRITE(x) { size_t bytes = write_utf8( dst, dstlen, x ); dst += bytes; dstlen -= bytes; if (numchars) { *numchars = *numchars + 1; } }
#define READ(x) ((*x++) & 0xFF)
#define PUT(x) *dst++ = (char)((x) & 0xFF); dstlen--;

#define ESCAPE_CHAR 0x00

size_t write_utf8( char* dst, size_t dstlen, int x ) {
    if (x < 0x80) {
        assert( dstlen >= 1 );
        *dst++ = (char)x;
        return 1;
    }
    if (x < 0x800) {
        assert( dstlen >= 2 );
        *dst++ = (char)(0xC0 | ((x >> 6) & 0x1F));
        *dst++ = (char)(0x80 | (x & 0x3F));
        return 2;
    }
    if (x < 0x10000) {
        assert( dstlen >= 3 );
        *dst++ = (char)(0xE0 | ((x >> 12) & 0x0F));
        *dst++ = (char)(0x80 | ((x >> 6) & 0x3F));
        *dst++ = (char)(0x80 | (x & 0x3F));
        return 3;
    }
    abort();
    return 0;
}

size_t pack( char* dst, size_t dstlen, char* src, size_t srclen, size_t* numchars ) {
    if (numchars) {
        *numchars = 0;
    }

    char* dst_orig = dst;
    while (srclen > 1) {
        int pair = 0;
        pair = READ(src);
        pair = (pair << 8) | READ(src);
        srclen -= 2;

        if (pair == 0x0000) {
            WRITE( ESCAPE_CHAR );
            WRITE( 0x0000 );
        } else if (pair >= 0xD800 && pair <= 0xDFFF) {
            WRITE( ESCAPE_CHAR );
            WRITE( 0x0001 + (pair - 0xD800) );
        } else if (pair >= 0xFFFE && pair <= 0xFFFF) {
            WRITE( ESCAPE_CHAR );
            WRITE( 0x0801 + (pair - 0xFFFE) );
        } else {
            WRITE( pair );
        }
    }
    if (srclen > 0) {
        WRITE( ESCAPE_CHAR );
        WRITE( 0x0803 + READ(src) );
    }
    return dst - dst_orig;
}

size_t unpack( char* dst, size_t dstlen, char* src, size_t srclen ) {
    char* dst_orig = dst;
    while (srclen > 0) {
        int escaped = 0;
        int c = READ(src);
        if (c == ESCAPE_CHAR) {
            escaped = 1;
            srclen--;
            c = READ(src);
        }

        if ((c & 0x80) == 0) {
            srclen--;
        } else if ((c & 0xE0) == 0xC0) {
            assert( srclen > 1 );
            c = (c & 0x1F) << 6;
            c |= (READ(src) & 0x3F);
            srclen -= 2;
        } else if ((c & 0xF0) == 0xE0) {
            assert( srclen > 2 );
            c = (c & 0xF) << 12;
            c |= ((READ(src) & 0x3F) << 6);
            c |= (READ(src) & 0x3F);
            srclen -= 3;
        } else {
            abort();
        }

        if (escaped) {
            if (c >= 0x0803) {
                assert( dstlen >= 1 );
                PUT( c - 0x0803 );
                assert( srclen == 0 );
                continue;
            } else if (c >= 0x0801) {
                c = (c - 0x0801) + 0xFFFE;
            } else if (c >= 0x0001) {
                c = (c - 0x0001) + 0xD800;
            }
        }

        assert( dstlen >= 2 );
        PUT( c >> 8 );
        PUT( c );
    }
    return dst - dst_orig;
}

#ifdef TEST
int main( int argc, char** argv ) {
    char* dst = malloc( 1024 );
    char* src = malloc( 256 );
    int i;
    for (i = 0; i < 256; i++) {
        src[i] = (char)i;
    }
    size_t chars;
    size_t dstlen = pack( dst, 1024, src, 256, &chars );
    printf( "Packed the 256 bytes into %lu utf-8 bytes (%lu Unicode chars)\n", dstlen, chars );
    dst[ dstlen ] = 0;
    printf( "Here is the string: %s\n", dst );
    char* unpacked = malloc( 256 );
    assert( 256 == unpack( unpacked, 256, dst, dstlen ) );
    for (i = 0; i < 256; i++) {
        assert( unpacked[i] == src[i] );
    }
    printf( "Round trip successful.\n" );
    return 0;
}
#endif
