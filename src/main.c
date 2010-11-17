#include <strings.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#define GCRYPT_NO_MPI_MACROS
#define GCRYPT_NO_DEPRECATED
#include "gcrypt.h"

#define CHECK_GCRY(x) { gcry_error_t ret = (x); if (ret) { fprintf( stderr, "Error %s in %s on line %d\n", gcry_strerror( ret ), gcry_strsource( ret ), __LINE__ ); abort(); } }
#define CHECK_SYS(x) { if ((x) < 0) { fprintf( stderr, "Error %s on line %d\n", strerror( errno ), __LINE__ ); abort(); } }

#define SAVE_PUBLIC_KEY

#define KEY_BUFLEN 1024
#define ASYMM_KEY_BITS 1024
#define AES_BLOCK_SIZE 16
#define AES_INIT_VECTOR "___twitsecret___"
#define AES_PADDING_CHAR ' '

int init_gcrypt() {
    if (! gcry_check_version( GCRYPT_VERSION )) {
        fprintf( stderr, "Error: libgcrypt version mismatch\n" );
        return 1;
    }
    CHECK_GCRY( gcry_control( GCRYCTL_INIT_SECMEM, 16384, 0 ) );
    CHECK_GCRY( gcry_control( GCRYCTL_INITIALIZATION_FINISHED, 0 ) );
    return 0;
}

void hexdump( char* dest, char* src, int srclen ) {
    int c;
    while (srclen-- > 0) {
        c = (*src >> 4) & 0x0F;
        *dest++ = (char)(c < 10 ? '0' + c : 'a' + c - 10);
        c = (*src++) & 0x0F;
        *dest++ = (char)(c < 10 ? '0' + c : 'a' + c - 10);
    }
    *dest = 0;
}

char* mkfilename( char* username, const char* extension ) {
    char* filename = malloc( 2 * strlen( username ) + strlen( extension ) + 1 );
    hexdump( filename, username, strlen( username ) );
    strcat( filename, extension );
    return filename;
}

void writefile( char* filename, void* data, size_t datalen ) {
    int outfile = open( filename, O_WRONLY | O_TRUNC | O_CREAT );
    CHECK_SYS( outfile );
    CHECK_SYS( write( outfile, data, datalen ) );
    CHECK_SYS( close( outfile ) );
}

int gen_keys( char* username, char* password ) {
    if (init_gcrypt()) {
        return 1;
    }

    gcry_sexp_t pubkey, seckey;

    {   // generate keypair
        gcry_sexp_t key_parms, keys;
        CHECK_GCRY( gcry_sexp_build( &key_parms, NULL, "(genkey (rsa (nbits %d)))", ASYMM_KEY_BITS ) );
        CHECK_GCRY( gcry_pk_genkey( &keys, key_parms ) );
        assert( pubkey = gcry_sexp_find_token( keys, "public-key", 0 ) );
        assert( seckey = gcry_sexp_find_token( keys, "private-key", 0 ) );
        gcry_sexp_release( key_parms );
        gcry_sexp_release( keys );
    }

    {   // write private key to file
        void* seckeytext = malloc( KEY_BUFLEN );
        size_t seckeylen = gcry_sexp_sprint( seckey, 0, seckeytext, KEY_BUFLEN );
        assert( seckeylen < KEY_BUFLEN );

        {   // pad private key s-expression to block size
            while ((seckeylen % AES_BLOCK_SIZE) != 0) {
                *(( (char*)seckeytext ) + seckeylen) = AES_PADDING_CHAR;
                seckeylen++;
            }
            *(( (char*)seckeytext ) + seckeylen) = 0;
        }

        {   // encrypt private key using password
            gcry_cipher_hd_t cipher;
            CHECK_GCRY( gcry_cipher_open( &cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE ) );

            {   // pad the password to block size
                char* password_padded = malloc( AES_BLOCK_SIZE );
                int i = 0;
                while (i < AES_BLOCK_SIZE) {
                    int to_copy = strlen( password );
                    if (AES_BLOCK_SIZE - i < to_copy) {
                        to_copy = AES_BLOCK_SIZE - i;
                    }
                    strncpy( password_padded + i, password, to_copy );
                    i += to_copy;
                }
                CHECK_GCRY( gcry_cipher_setkey( cipher, password_padded, AES_BLOCK_SIZE ) );
                free( password_padded );
            }

            assert( strlen( AES_INIT_VECTOR ) == AES_BLOCK_SIZE );
            CHECK_GCRY( gcry_cipher_setiv( cipher, AES_INIT_VECTOR, AES_BLOCK_SIZE ) );
            CHECK_GCRY( gcry_cipher_encrypt( cipher, seckeytext, seckeylen, NULL, 0 ) );
            gcry_cipher_close( cipher );
        }

        {   // do write to file
            char* filename = mkfilename( username, ".key" );
            writefile( filename, seckeytext, seckeylen );
            free( filename );
        }

        free( seckeytext );
    }

    {   // publish public key
        void* pubkeytext = malloc( KEY_BUFLEN );
        size_t pubkeylen = gcry_sexp_sprint( pubkey, 0, pubkeytext, KEY_BUFLEN );
        assert( pubkeylen < KEY_BUFLEN );

        {   // do write to file
            char* filename = mkfilename( username, ".pub" );
            writefile( filename, pubkeytext, pubkeylen );
            free( filename );
        }

        free( pubkeytext );
    }

    gcry_sexp_release( pubkey );
    gcry_sexp_release( seckey );
    return 0;
}

int test_encrypt( char* username, char* message ) {
    gcry_sexp_t pubkey;

    {   // get the public key
        void* pubkeytext = malloc( KEY_BUFLEN );
        int pubkeylen = 0;

        {   // read the key from file
            char* filename = mkfilename( username, ".pub" );
            int infile = open( filename, O_RDONLY );
            CHECK_SYS( infile );
            CHECK_SYS( pubkeylen = read( infile, pubkeytext, KEY_BUFLEN ) );
            assert( pubkeylen < KEY_BUFLEN );
            CHECK_SYS( close( infile ) );
            free( filename );
        }

        CHECK_GCRY( gcry_sexp_new( &pubkey, pubkeytext, pubkeylen, 0 ) );
        free( pubkeytext );
    }

    void* tweet = malloc( 1024 );
    int tweetlen = 0;

    {   // generate the symmetric key
        gcry_mpi_t symkey = gcry_mpi_new( ASYMM_KEY_BITS );
        gcry_mpi_randomize( symkey, ASYMM_KEY_BITS, GCRY_STRONG_RANDOM );

        {   // write the pubkey-encrypted symkey to tweet
            gcry_sexp_t plaintext, ciphertext;
            CHECK_GCRY( gcry_sexp_build( &plaintext, NULL, "(data (flags raw) (value %m))", symkey ) );
            CHECK_GCRY( gcry_pk_encrypt( &ciphertext, plaintext, pubkey ) );
            tweetlen += gcry_sexp_sprint( ciphertext, 0, tweet, 1024 - tweetlen );
        }

        {
            char* filename = mkfilename( username, ".msg" );
            writefile( filename, tweet, tweetlen );
            free( filename );
        }

        gcry_free( symkey );
    }

    return 0;
}

int usage() {
    printf( "Usage: twitsecret <command> [command-args]\n" );
    printf( "Commands:\n" );
    printf( "   init <username> <password>\n" );
    printf( "       Generates a new twitsecret ECDSA keypair for the user. Also publishes the public key\n" );
    printf( "       and saves the private key to ~/.twitsecret/<file>.key, where <file> is the base-64\n" );
    printf( "       encoding of <username>\n" );
    printf( "   test <username> <message>\n" );
    printf( "       Encrypt the message using the pubkey belonging to user\n" );
    return 1;
}

int main( int argc, char** argv ) {
    if (argc == 4 && strcasecmp( argv[1], "init" ) == 0) {
        return gen_keys( argv[2], argv[3] );
    } else if (argc == 4 && strcasecmp( argv[1], "test" ) == 0) {
        return test_encrypt( argv[2], argv[3] );
    }
    return usage();
}
