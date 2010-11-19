#include <strings.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#define GCRYPT_NO_MPI_MACROS
#define GCRYPT_NO_DEPRECATED
#include "gcrypt.h"

#define KEY_BUFLEN 1024
#define MSG_BUFLEN 1024
#define ASYMM_KEY_BITS 1024
#define SYMM_KEY_BYTES (ASYMM_KEY_BITS/8)
#define SYMM_KEY_PLACEHOLDER "128:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#define AES_BLOCK_SIZE 16
#define AES_INIT_VECTOR "___twitsecret___"
#define AES_PADDING_CHAR ' '
#define MAX_MESSAGE_LENGTH 140

#define CHECK_GCRY(x) { gcry_error_t ret = (x); if (ret) { fprintf( stderr, "Error %s in %s on line %d\n", gcry_strerror( ret ), gcry_strsource( ret ), __LINE__ ); abort(); } }
#define CHECK_SYS(x) { if ((x) < 0) { fprintf( stderr, "Error %s on line %d\n", strerror( errno ), __LINE__ ); abort(); } }

int twit_init_gcrypt() {
    if (! gcry_check_version( GCRYPT_VERSION )) {
        fprintf( stderr, "Error: libgcrypt version mismatch\n" );
        return 1;
    }
    CHECK_GCRY( gcry_control( GCRYCTL_INIT_SECMEM, 16384, 0 ) );
    CHECK_GCRY( gcry_control( GCRYCTL_INITIALIZATION_FINISHED, 0 ) );
    return 0;
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

size_t twit_pad_plaintext( char* msgtext, size_t msglen ) {
    while ((msglen % AES_BLOCK_SIZE) != 0) {
        *(msgtext + msglen) = AES_PADDING_CHAR;
        msglen++;
    }
    *(msgtext + msglen) = 0;
    return msglen;
}

char* twit_pad_password( char* password, size_t passwordlen ) {
    char* password_padded = malloc( AES_BLOCK_SIZE );
    int i = 0;
    while (i < AES_BLOCK_SIZE) {
        int to_copy = passwordlen;
        if (AES_BLOCK_SIZE - i < to_copy) {
            to_copy = AES_BLOCK_SIZE - i;
        }
        memcpy( password_padded + i, password, to_copy );
        i += to_copy;
    }
    return password_padded;
}

size_t twit_encrypt( char* msgtext, size_t msglen, char* password, size_t passwordlen ) {
    msglen = twit_pad_plaintext( msgtext, msglen );
    char* password_padded = (passwordlen != AES_BLOCK_SIZE ? twit_pad_password( password, passwordlen ) : password);

    gcry_cipher_hd_t cipher;
    CHECK_GCRY( gcry_cipher_open( &cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, GCRY_CIPHER_SECURE ) );
    CHECK_GCRY( gcry_cipher_setkey( cipher, password_padded, AES_BLOCK_SIZE ) );
    assert( strlen( AES_INIT_VECTOR ) == AES_BLOCK_SIZE );
    CHECK_GCRY( gcry_cipher_setiv( cipher, AES_INIT_VECTOR, AES_BLOCK_SIZE ) );
    CHECK_GCRY( gcry_cipher_encrypt( cipher, msgtext, msglen, NULL, 0 ) );
    gcry_cipher_close( cipher );

    if (passwordlen != AES_BLOCK_SIZE) free( password_padded );
    return msglen;
}

void twit_hexdump( char* dest, char* src, int srclen ) {
    int c;
    while (srclen-- > 0) {
        c = (*src >> 4) & 0x0F;
        *dest++ = (char)(c < 10 ? '0' + c : 'a' + c - 10);
        c = (*src++) & 0x0F;
        *dest++ = (char)(c < 10 ? '0' + c : 'a' + c - 10);
    }
    *dest = 0;
}

char* twit_mkfilename( char* username, const char* extension ) {
    char* filename = malloc( 2 * strlen( username ) + strlen( extension ) + 1 );
    twit_hexdump( filename, username, strlen( username ) );
    strcat( filename, extension );
    return filename;
}

void twit_writefile( char* filename, char* data, size_t datalen ) {
    int outfile = open( filename, O_WRONLY | O_TRUNC | O_CREAT );
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

int twit_gen_keys( char* username, char* password ) {
    if (twit_init_gcrypt()) {
        return 1;
    }

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
        void* pubkeytext = malloc( KEY_BUFLEN );
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
    return 0;
}

int twit_test_encrypt( char* username, char* message ) {
    assert( strlen( message ) <= MAX_MESSAGE_LENGTH );

    gcry_sexp_t pubkey;

    {   // get the public key
        void* pubkeytext = malloc( KEY_BUFLEN );
        int pubkeylen = 0;

        {   // read the key from file
            char* filename = twit_mkfilename( username, ".pub" );
            pubkeylen = twit_readfile( filename, pubkeytext, KEY_BUFLEN );
            assert( pubkeylen < KEY_BUFLEN );
            free( filename );
        }

        CHECK_GCRY( gcry_sexp_new( &pubkey, pubkeytext, pubkeylen, 0 ) );
        free( pubkeytext );
    }

    char* tweet = malloc( MSG_BUFLEN );
    int tweetlen = 0;

    {   // generate the symmetric key
        char* symkey = malloc( SYMM_KEY_BYTES );
        gcry_randomize( symkey, SYMM_KEY_BYTES, GCRY_STRONG_RANDOM );

        {   // write the pubkey-encrypted symkey to tweet
            char* sexptext = malloc( SYMM_KEY_BYTES + 64 );
            strcpy( sexptext, "(data (flags raw) (value " SYMM_KEY_PLACEHOLDER "))" );
            size_t sexplen = strlen( sexptext );
            memcpy( strstr( sexptext, "X" ), symkey, SYMM_KEY_BYTES );
            {
                gcry_sexp_t plaintext, ciphertext;
                CHECK_GCRY( gcry_sexp_new( &plaintext, sexptext, sexplen, 0 ) );
                CHECK_GCRY( gcry_pk_encrypt( &ciphertext, plaintext, pubkey ) );
                tweetlen += gcry_sexp_sprint( ciphertext, 0, tweet, MSG_BUFLEN - tweetlen );
                gcry_sexp_release( ciphertext );
                gcry_sexp_release( plaintext );
            }
            free( sexptext );
        }

        {   // write the symkey-encrypted msg to tweet
            char* msgtext = malloc( MSG_BUFLEN );
            strcpy( msgtext, message );
            size_t msglen = twit_encrypt( msgtext, strlen( msgtext ), symkey, SYMM_KEY_BYTES );
            memcpy( tweet + tweetlen, msgtext, msglen );
            tweetlen += msglen;
            free( msgtext );
        }

        {   // write to file
            char* filename = twit_mkfilename( username, ".msg" );
            twit_writefile( filename, tweet, tweetlen );
            free( filename );
        }

        free( symkey );
    }

    free( tweet );
    return 0;
}

int twit_usage() {
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
        return twit_gen_keys( argv[2], argv[3] );
    } else if (argc == 4 && strcasecmp( argv[1], "test" ) == 0) {
        return twit_test_encrypt( argv[2], argv[3] );
    }
    return twit_usage();
}
