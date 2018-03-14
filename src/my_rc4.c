#ifndef BOOL_H
#define BOOL_H

typedef int bool;
#define true 1
#define false 0

#endif

#include <openssl/rc4.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFSIZE 1024
#define SALTSIZE 8


bool do_encrypt = true;
bool is_salted = true;

void handle_err(char * err)
{
    fputs(err, stderr);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

int main(int argc, char * argv[])
{
    int opt;
    int long_index = 0;
    static struct option long_options[] = {
        {"e",       no_argument,        &do_encrypt,true},
        {"d",       no_argument,        &do_encrypt,false},
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
                fprintf(stderr, "Usage: %s [-ed] [-nosalt] -in <input file path> -out <output file path> -k <encryption/decryption key>", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    FILE * in = (in_path == NULL) ? stdin : fopen(in_path, "r");
    if(in == NULL)
        handle_err("failed to open read file");

    FILE * out = (out_path == NULL) ? stdout : fopen(out_path, "w");
    if(out == NULL)
        handle_err("failed to open write file");

    char buffer[BUFFSIZE];
    char saltbuff[SALTSIZE], * salt;

    if(!is_salted)
        salt = NULL;
    else
    {
        if(do_encrypt)
        {
            if(RAND_bytes(saltbuff, sizeof saltbuff) == 0)
                handle_err("failed to generate salt");
            
            fwrite(saltbuff, sizeof(char), SALTSIZE, out);
        }
        else //Read salt from input
            if(fread(saltbuff, sizeof(char), SALTSIZE, in) == -1)
                handle_err("failed to read salt from file");

        salt = saltbuff;
    }

    const EVP_CIPHER * cipher = EVP_rc4();
    const EVP_MD * digest = EVP_md5();

    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    EVP_BytesToKey(cipher, digest, salt, keystr, strlen(keystr), 1, key, iv); //Replace

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, do_encrypt);

    char inbuff[BUFFSIZE], outbuff[BUFFSIZE + EVP_MAX_BLOCK_LENGTH];
    int readlen, writelen;
    
    for(;;)
    {
        readlen = fread(inbuff, 1, BUFFSIZE, in);
        
        if(readlen <= 0) break; //We've finished
        
        if(EVP_CipherUpdate(&ctx, outbuff, &writelen, inbuff, readlen) == 0)
        {
            EVP_CIPHER_CTX_cleanup(&ctx);
            handle_err("Error while encrypting/decryption");
        }
        
        fwrite(outbuff, 1, writelen, out);
    }

    if(EVP_CipherFinal_ex(&ctx, outbuff, &writelen) == 0)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        handle_err("Error while encrypting/decryption");
    }
    
    fwrite(outbuff, sizeof(char), writelen, out);
    EVP_CIPHER_CTX_cleanup(&ctx);

    exit(EXIT_SUCCESS);

}
