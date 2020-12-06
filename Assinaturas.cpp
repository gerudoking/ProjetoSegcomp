/*
=========================================================
    Trabalho da Disciplina de Segurança Computacional
        Gerador e Verificador de Assinaturas
=========================================================
Autor:      Eduardo de Azevedo dos Santos
Matrícula:  14/0136967
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <memory>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define KEYFILE     "private_key.pem"
#define SIGNFILE    "cipher_message.txt"
#define BUFFSIZE    80
#define KEYSIZE     2048

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

const char* pcszPassphrase = "42"; //Resposta para a vida, o universo e tudo mais

//Função para obter o erro relacionado a OpenSSL
std::string getOpenSSLError(EVP_MD_CTX* mdctx, unsigned char **sig){
    //Limpeza
    if(*sig)
        OPENSSL_free(*sig);
    if(mdctx)
        EVP_MD_CTX_destroy(mdctx);

    //Retorno com o erro
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

//Função para leitura da chave
EVP_PKEY *ReadPKeyFromFile(const char * fname)
{
    EVP_PKEY *key = NULL;
    FILE *fp = fopen(fname, "r");

    if(!fp) {
        perror(fname);
        return NULL;
    }

    key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

//Função para geração das chaves
void GenerateKeys(RSA* rsa){
    int rc;
    const EVP_CIPHER* pCipher = NULL;
    FILE* pFile = NULL;
    EVP_KEY_ptr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);

    BN_ptr bn(BN_new(), ::BN_free);

    rc = BN_set_word(bn.get(), RSA_F4);

    RSA_generate_key_ex(rsa, KEYSIZE, bn.get(), NULL);

    if(rsa && pKey.get() && EVP_PKEY_assign_RSA(pKey.get(),rsa))
    {
        if(RSA_check_key(rsa) <= 0)
        {
            fprintf(stderr,"RSA_check_key failed.\n");
            EVP_PKEY_free(pKey.get());
            pKey = NULL;
        }
    }

    if((pFile = fopen(KEYFILE, "wt")) && (pCipher = EVP_aes_256_cbc())){
        printf("[Key Generation] Writing key to file: %s\n", KEYFILE);

        PEM_write_PrivateKey(pFile,pKey.get(),pCipher, (unsigned char*)pcszPassphrase, (int)strlen(pcszPassphrase),NULL,NULL);
        fclose(pFile);
    }
}

//Função para assinar a mensagem
int SignMessage(EVP_PKEY *key, const unsigned char *msg, const size_t mlen,
            unsigned char **sig, size_t *slen) {

    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    if(!(mdctx = EVP_MD_CTX_create())){
        printf("[Signing] Error on context creation.\n%s\n", getOpenSSLError(mdctx, sig).c_str());
        exit(1);
    }

    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha3_256(), NULL, key)){
        printf("[Signing] Error on signing start.\n%s\n", getOpenSSLError(mdctx, sig).c_str());
        exit(1);
    }

    if(1 != EVP_DigestSignUpdate(mdctx, msg, mlen)){
        printf("[Signing] Error on signing update.\n%s\n", getOpenSSLError(mdctx, sig).c_str());
        exit(1);
    }

    if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)){
        printf("[Signing] Error obtaining lenth of signature.\n%s\n", getOpenSSLError(mdctx, sig).c_str());
        exit(1);
    }

    if(!(*sig = (unsigned char *)OPENSSL_malloc(*slen))){
        printf("[Signing] Error allocating memory for signed message.\n%s\n", getOpenSSLError(mdctx, sig).c_str());
        exit(1);
    }

    if(1 != EVP_DigestSignFinal(mdctx, *sig, slen)){
        printf("[Signing] Error obtaining signature.\n%s\n", getOpenSSLError(mdctx, sig).c_str());
        exit(1);
    }

    return 1;
}

//Função para escrever mensagem cifrada
void WriteSignedMessage(unsigned char* message){
    FILE* pFile = NULL;

    if(pFile = fopen(SIGNFILE, "wt")){
        printf("[Message Writing] Writing message to file: %s\n", SIGNFILE);
        fwrite(message, sizeof(unsigned char), sizeof(message), pFile);
        fclose(pFile);
    }
}

int main()
{
    int ret = EXIT_FAILURE;
    char *str = NULL;
    unsigned char *sig = NULL;
    size_t slen = 0;
    unsigned char msg[BUFFSIZE];
    size_t mlen = 0;
    RSA* rsa = RSA_new();

    printf("[Input] Please type a message:  ");
    scanf("%s", str);

    printf("[Key Generation] Starting key generation.\n");
    GenerateKeys(rsa);
    printf("[Key Generation] Key generation complete.\n");

    EVP_PKEY *key = ReadPKeyFromFile(KEYFILE);

    mlen = strlen((const char*)msg);

    printf("[Signing] Starting message signing.\n");
    SignMessage(key, msg, mlen, &sig, &slen);
    printf("[Signing] Message signing complete.\n");

    WriteSignedMessage(sig);

    OPENSSL_free(sig);
    EVP_PKEY_free(key);
    sig = NULL;

    printf("[Clean-Up] Cleaning up memory.\n");

    printf("DONE\n");

    return 0;
}