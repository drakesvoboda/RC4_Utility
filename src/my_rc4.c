#ifndef BOOL_H
#define BOOL_H

typedef int bool;
#define true 1
#define false 0

#endif

#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFSIZE (8*1024)
#define SALTSIZE 8

enum rc4_mode {ENCRYPT = 0, DECRYPT = 1};
enum rc4_mode mode;
bool is_salted = true;

void handle_err(void)
{
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main(int argc, char * argv[])
{
    int opt;
    int long_index = 0;
    static struct option long_options[] = {
        {"e",       no_argument,        &mode,      ENCRYPT},
        {"d",       no_argument,        &mode,      DECRYPT},
        {"nosalt",  no_argument,        &is_salted, false},
        {"in",      required_argument,  0,          'i'}, 
        {"out",     required_argument,  0,          'o'}, 
        {0, 0, 0, 0}
    };

    char * in_path = NULL, * out_path = NULL, * keystr = NULL;

    while ((opt = getopt_long_only(argc, argv, "i:o:k:", long_options, &long_index)) != -1) 
    {
        switch (opt) 
        {
            case 0: break;
            case 'i': in_path = optarg; break;
            case 'o': out_path = optarg; break;
            case 'k': keystr = optarg; break;
            case '?': break;
            default:
                fprintf(stderr, "Usage: %s [-ed] [-nosalt] -in 
                <input file path> -out <output file path> -k 
                <encryption/decryption key>", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    FILE * in = (in_path == NULL) ? stdin : fopen(in_path, "r");
    if(in == NULL)
        handle_err();

    FILE * out = (out_path == NULL) ? stdout : fopen(out_path, "a");
    if(out == NULL)
        handle_err();

    char buffer[BUFFSIZE];
    char salt[SALTSIZE];

    if(!is_salted)
        salt = NULL;
    else
    {
        if(mode == ENCRYPT)
            if(RAND_bytes(salt, sizeof salt) == 0)
                handle_err();
        else //Read salt from input
            if(read(in, salt, sizeof salt) == -1)
                handle_err();
    }

    const EVP_MD *digest = EVP_md5();

    EVP_BytesToKey(cipher, digest, salt, keystr, strlen(keystr), 1, key, iv);
}
