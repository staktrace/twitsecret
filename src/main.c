#include <strings.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>

#define GCRYPT_NO_MPI_MACROS
#define GCRYPT_NO_DEPRECATED
#include "gcrypt.h"

#include "zlib.h"

#define KEY_BUFLEN 1024
#define MSG_BUFLEN 4096
#define ASYMM_KEY_BITS 1024
#define SYMM_KEY_BYTES 16
#define AES_BLOCK_SIZE 16
#define AES_INIT_VECTOR "___twitsecret___"
#define AES_PADDING_CHAR ' '
#define MAX_MESSAGE_LENGTH 140
#define MAX_RECIPIENTS 255
#define TWIT_UNCOMPRESSED 0
#define TWIT_ZLIB 1

#define CHECK_GCRY(x) { gcry_error_t ret = (x); if (ret) { fprintf( stderr, "Error %d:%s in %s on line %d\n", gcry_err_code( ret ), gcry_strerror( ret ), gcry_strsource( ret ), __LINE__ ); abort(); } }
#define CHECK_SYS(x) { if ((x) < 0) { fprintf( stderr, "Error %s on line %d\n", strerror( errno ), __LINE__ ); abort(); } }
#define CHECK_ZLIB(x) { if ((x) != Z_OK) { fprintf( stderr, "Zlib error on line %d\n", __LINE__ ); abort(); } }

void twit_hexdump( char* dest, const char* src, int srclen ) {
    int c;
    while (srclen-- > 0) {
        c = (*src >> 4) & 0x0F;
        *dest++ = (char)(c < 10 ? '0' + c : 'a' + c - 10);
        c = (*src++) & 0x0F;
        *dest++ = (char)(c < 10 ? '0' + c : 'a' + c - 10);
    }
    *dest = 0;
}

void twit_dump( const char* src, int srclen ) {
    char* tmp = malloc( srclen * 2 + 1 );
    twit_hexdump( tmp, src, srclen );
    printf( "%s\n", tmp );
    free( tmp );
}

void twit_init_gcrypt() {
    if (! gcry_check_version( GCRYPT_VERSION )) {
        fprintf( stderr, "Error: libgcrypt version mismatch: compiled with %s, runtime is %s\n", GCRYPT_VERSION, gcry_check_version(0) );
        abort();
    }
    CHECK_GCRY( gcry_control( GCRYCTL_INIT_SECMEM, 16384, 0 ) );
    CHECK_GCRY( gcry_control( GCRYCTL_ENABLE_QUICK_RANDOM ) );
    CHECK_GCRY( gcry_control( GCRYCTL_INITIALIZATION_FINISHED, 0 ) );
}

void twit_generate_keypair( gcry_sexp_t* pubkey, gcry_sexp_t* seckey ) {
    gcry_sexp_t key_parms, keys;
    CHECK_GCRY( gcry_sexp_build( &key_parms, NULL, "(genkey (rsa (nbits %d)))", ASYMM_KEY_BITS ) );
    CHECK_GCRY( gcry_pk_genkey( &keys, key_parms ) );
    assert( *pubkey = gcry_sexp_find_token( keys, "public-key", 0 ) );
    assert( *seckey = gcry_sexp_find_token( keys, "private-key", 0 ) );
    gcry_sexp_release( key_parms );
    gcry_sexp_release( keys );
}

size_t twit_pad_plaintext( char* plaintext, size_t plainlen ) {
    while ((plainlen % AES_BLOCK_SIZE) != 0) {
        *(plaintext + plainlen) = AES_PADDING_CHAR;
        plainlen++;
    }
    *(plaintext + plainlen) = 0;
    return plainlen;
}

char* twit_pad_password( char* password, size_t passlen ) {
    char* password_padded = malloc( AES_BLOCK_SIZE );
    int i = 0;
    while (i < AES_BLOCK_SIZE) {
        int to_copy = passlen;
        if (AES_BLOCK_SIZE - i < to_copy) {
            to_copy = AES_BLOCK_SIZE - i;
        }
        memcpy( password_padded + i, password, to_copy );
        i += to_copy;
    }
    return password_padded;
}

size_t twit_encrypt( char* plaintext, size_t plainlen, char* password, size_t passlen ) {
    plainlen = twit_pad_plaintext( plaintext, plainlen );
    char* password_padded = (passlen != AES_BLOCK_SIZE ? twit_pad_password( password, passlen ) : password);

    gcry_cipher_hd_t cipher;
    CHECK_GCRY( gcry_cipher_open( &cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE ) );
    CHECK_GCRY( gcry_cipher_setkey( cipher, password_padded, AES_BLOCK_SIZE ) );
    assert( strlen( AES_INIT_VECTOR ) == AES_BLOCK_SIZE );
    CHECK_GCRY( gcry_cipher_setiv( cipher, AES_INIT_VECTOR, AES_BLOCK_SIZE ) );
    CHECK_GCRY( gcry_cipher_encrypt( cipher, plaintext, plainlen, NULL, 0 ) );
    gcry_cipher_close( cipher );

    if (passlen != AES_BLOCK_SIZE) free( password_padded );
    return plainlen;
}

size_t twit_decrypt( char* ciphertext, size_t cipherlen, char* password, size_t passlen ) {
    char* password_padded = (passlen != AES_BLOCK_SIZE ? twit_pad_password( password, passlen ) : password);

    gcry_cipher_hd_t cipher;
    CHECK_GCRY( gcry_cipher_open( &cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE ) );
    CHECK_GCRY( gcry_cipher_setkey( cipher, password_padded, AES_BLOCK_SIZE ) );
    assert( strlen( AES_INIT_VECTOR ) == AES_BLOCK_SIZE );
    CHECK_GCRY( gcry_cipher_setiv( cipher, AES_INIT_VECTOR, AES_BLOCK_SIZE ) );
    CHECK_GCRY( gcry_cipher_decrypt( cipher, ciphertext, cipherlen, NULL, 0 ) );
    gcry_cipher_close( cipher );

    if (passlen != AES_BLOCK_SIZE) free( password_padded );

    while (ciphertext[ cipherlen - 1 ] == ' ') {
        cipherlen--;
    }
    ciphertext[ cipherlen ] = 0;
    return cipherlen;
}

char* twit_mkfilename( char* username, const char* extension ) {
    char* filename = malloc( 2 * strlen( username ) + strlen( extension ) + 1 );
    twit_hexdump( filename, username, strlen( username ) );
    strcat( filename, extension );
    return filename;
}

void twit_writefile( char* filename, char* data, size_t datalen ) {
    int outfile = open( filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR );
    CHECK_SYS( outfile );
    CHECK_SYS( write( outfile, data, datalen ) );
    CHECK_SYS( close( outfile ) );
}

int twit_readfile( char* filename, char* dest, size_t destlen ) {
    int readlen;
    int infile = open( filename, O_RDONLY );
    CHECK_SYS( infile );
    CHECK_SYS( readlen = read( infile, dest, destlen ) );
    CHECK_SYS( close( infile ) );
    return readlen;
}

void twit_gen_keys( char* username, char* password ) {
    twit_init_gcrypt();

    gcry_sexp_t pubkey, seckey;
    twit_generate_keypair( &pubkey, &seckey );

    {   // write private key to file
        char* seckeytext = malloc( KEY_BUFLEN );
        size_t seckeylen = gcry_sexp_sprint( seckey, 0, seckeytext, KEY_BUFLEN );
        assert( seckeylen < KEY_BUFLEN );
        seckeylen = twit_encrypt( seckeytext, seckeylen, password, strlen( password ) );

        {   // write to file
            char* filename = twit_mkfilename( username, ".key" );
            twit_writefile( filename, seckeytext, seckeylen );
            free( filename );
        }

        free( seckeytext );
    }

    {   // publish public key
        char* pubkeytext = malloc( KEY_BUFLEN );
        size_t pubkeylen = gcry_sexp_sprint( pubkey, 0, pubkeytext, KEY_BUFLEN );
        assert( pubkeylen < KEY_BUFLEN );

        {   // write to file
            char* filename = twit_mkfilename( username, ".pub" );
            twit_writefile( filename, pubkeytext, pubkeylen );
            free( filename );
        }

        free( pubkeytext );
    }

    gcry_sexp_release( pubkey );
    gcry_sexp_release( seckey );
}

void twit_test_encrypt( char* message, char** usernames, int usernamecount ) {
    assert( strlen( message ) <= MAX_MESSAGE_LENGTH );
    assert( usernamecount <= MAX_RECIPIENTS );

    char* tweet = malloc( MSG_BUFLEN );
    int tweetlen = 0;

    tweet[ tweetlen++ ] = (char)usernamecount;

    // generate the symmetric key
    char* symkey = malloc( SYMM_KEY_BYTES );
    gcry_randomize( symkey, SYMM_KEY_BYTES, GCRY_STRONG_RANDOM );

    int i;
    for (i = 0; i < usernamecount; i++) {
        gcry_sexp_t pubkey;

        {   // get the public key
            char* pubkeytext = malloc( KEY_BUFLEN );
            int pubkeylen = 0;

            {   // read the key from file
                char* filename = twit_mkfilename( usernames[i], ".pub" );
                pubkeylen = twit_readfile( filename, pubkeytext, KEY_BUFLEN );
                assert( pubkeylen < KEY_BUFLEN );
                free( filename );
            }

            CHECK_GCRY( gcry_sexp_new( &pubkey, pubkeytext, pubkeylen, 0 ) );
            free( pubkeytext );
        }

        {   // write the pubkey-encrypted symkey to tweet
            gcry_sexp_t symkeycipher;

            {   // generate the encrypted symkey
                gcry_sexp_t symkeydata;
                size_t personalizedlen = strlen( usernames[i] ) + 1 + SYMM_KEY_BYTES;
                char* personalized = malloc( personalizedlen );

                strcpy( personalized, usernames[i] );
                strcat( personalized, "@" );
                memcpy( personalized + strlen( personalized ), symkey, SYMM_KEY_BYTES );
                CHECK_GCRY( gcry_sexp_build( &symkeydata, 0, "(data (flags raw) (value %b))", personalizedlen, personalized ) );
                CHECK_GCRY( gcry_pk_encrypt( &symkeycipher, symkeydata, pubkey ) );

                gcry_sexp_release( symkeydata );
                free( personalized );
            }

            {   // extract the encrypted symkey bytes and write to tweet
                gcry_sexp_t symkeydata;
                const char* symkeyptr;
                size_t symkeylen;

                assert( symkeydata = gcry_sexp_find_token( symkeycipher, "a", 0 ) );
                assert( symkeyptr = gcry_sexp_nth_data( symkeydata, 1, &symkeylen ) );

                memcpy( tweet + tweetlen, &symkeylen, sizeof(symkeylen) );
                tweetlen += sizeof(symkeylen);
                memcpy( tweet + tweetlen, symkeyptr, symkeylen );
                tweetlen += symkeylen;

                gcry_sexp_release( symkeydata );
            }
            gcry_sexp_release( symkeycipher );
        }

        gcry_sexp_release( pubkey );
    }

    {   // write the symkey-encrypted msg to tweet
        char* msgtext = malloc( MSG_BUFLEN );
        *msgtext = TWIT_UNCOMPRESSED;
        strcpy( msgtext + 1, message );
        size_t msglen = strlen( message ) + 1;

        {
            size_t compressedSize = compressBound( msglen );
            char* compressed = malloc( compressedSize );
            CHECK_ZLIB( compress2( (unsigned char*)compressed, &compressedSize, (unsigned char*)(msgtext + 1), (msglen - 1), Z_BEST_COMPRESSION ) );
            if (compressedSize + 1 < msglen) {
printf( "Compressing\n" );
                *msgtext = TWIT_ZLIB;
                memcpy( msgtext + 1, compressed, compressedSize );
                msglen = compressedSize + 1;
            }
            free( compressed );
        }

        msglen = twit_encrypt( msgtext, msglen, symkey, SYMM_KEY_BYTES );
        memcpy( tweet + tweetlen, msgtext, msglen );
        tweetlen += msglen;
        free( msgtext );
    }

    twit_writefile( "twitsecret.msg", tweet, tweetlen );

    free( symkey );
    free( tweet );
}

void twit_test_decrypt( char* username, char* password ) {
    gcry_sexp_t seckey;

    {   // get the secret key
        void* seckeytext = malloc( KEY_BUFLEN );
        int seckeylen = 0;

        {   // read the key from file
            char* filename = twit_mkfilename( username, ".key" );
            seckeylen = twit_readfile( filename, seckeytext, KEY_BUFLEN );
            assert( seckeylen < KEY_BUFLEN );
            free( filename );
        }

        seckeylen = twit_decrypt( seckeytext, seckeylen, password, strlen( password ) );
        CHECK_GCRY( gcry_sexp_new( &seckey, seckeytext, seckeylen, 0 ) );

        free( seckeytext );
    }

    char* tweet = malloc( MSG_BUFLEN );
    int tweetlen = twit_readfile( "twitsecret.msg", tweet, MSG_BUFLEN );
    int tweetix = 0;

    char* symkey = malloc( SYMM_KEY_BYTES );

    int numusers = tweet[ tweetix++ ] & 0xFF;

    int found = 0;
    int i;
    for (i = 0; i < numusers; i++) {
        // parse the symmetric key and decrypt it
        size_t cipherlen;
        memcpy( &cipherlen, tweet + tweetix, sizeof(cipherlen) );
        tweetix += sizeof(cipherlen);

        if (found == 0) {
            // try decrypting the pubkey-encrypted symkey to see if it matches the username
            gcry_sexp_t symkeydata, symkeyplain;
            const char* symkeyptr;
            size_t symkeylen;

            CHECK_GCRY( gcry_sexp_build( &symkeydata, 0, "(enc-val (rsa (a %b)))", cipherlen, tweet + tweetix ) );
            tweetix += cipherlen;
            CHECK_GCRY( gcry_pk_decrypt( &symkeyplain, symkeydata, seckey ) );
            gcry_sexp_release( symkeydata );

            assert( symkeyptr = gcry_sexp_nth_data( symkeyplain, 0, &symkeylen ) );
            if (symkeylen == strlen( username ) + 1 + SYMM_KEY_BYTES && memcmp( symkeyptr, username, strlen( username ) ) == 0 && symkeyptr[ strlen( username ) ] == '@') {
                memcpy( symkey, symkeyptr + strlen( username ) + 1, symkeylen - strlen( username ) - 1 );
                found = 1;
            }
            gcry_sexp_release( symkeyplain );
        } else {
            // already found the symkey, skip past the other pubkey-encrypted symkeys
            tweetix += cipherlen;
        }
    }

    if (found) {
        // parse the message and decrypt it
        char* msgtext = malloc( MSG_BUFLEN );
        size_t msglen = tweetlen - tweetix;
        assert( msglen <= MSG_BUFLEN );
        memcpy( msgtext, tweet + tweetix, msglen );
        msglen = twit_decrypt( msgtext, msglen, symkey, SYMM_KEY_BYTES );

        if (*msgtext == TWIT_ZLIB) {
            size_t uncompressedlen = MSG_BUFLEN;
            char* uncompressed = malloc( uncompressedlen );
            CHECK_ZLIB( uncompress( (unsigned char*)uncompressed, &uncompressedlen, (unsigned char*)(msgtext + 1), msglen - 1 ) );
            memcpy( msgtext + 1, uncompressed, uncompressedlen );
            msglen = uncompressedlen + 1;
            *msgtext = TWIT_UNCOMPRESSED;
            free( uncompressed );
        }

        printf( "message: %s\n", msgtext + 1 );
        free( msgtext );
    } else {
        printf( "error: unable to decrypt message\n" );
    }

    free( symkey );
    free( tweet );
    gcry_sexp_release( seckey );
}

void twit_usage() {
    printf( "Usage: twitsecret <command> [command-args]\n" );
    printf( "Commands:\n" );
    printf( "   init <username> <password>\n" );
    printf( "       Generates a new keypair for the user\n" );
    printf( "   enc <message> [<username> [<username> [...]]]\n" );
    printf( "       Encrypt the message using the pubkeys belonging to the specified users\n" );
    printf( "   dec <username> <password>\n" );
    printf( "       Decrypt the message using the seckey belonging to user\n" );
}

int main( int argc, char** argv ) {
    if (argc == 4 && strcasecmp( argv[1], "init" ) == 0) {
        twit_gen_keys( argv[2], argv[3] );
    } else if (argc >= 3 && strcasecmp( argv[1], "enc" ) == 0) {
        twit_test_encrypt( argv[2], argv + 3, argc - 3 );
    } else if (argc == 4 && strcasecmp( argv[1], "dec" ) == 0) {
        twit_test_decrypt( argv[2], argv[3] );
    } else {
        twit_usage();
    }
    return 0;
}
