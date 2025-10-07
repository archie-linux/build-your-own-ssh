#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

// Logging function
void log_message(const char *msg) {
    FILE *log = fopen("ssh_client.log", "a");
    if (log) {
        fprintf(log, "%s\n", msg);
        fclose(log);
    }
}

// Initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Create SSL context
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_message("Unable to create SSL context");
        exit(1);
    }
    return ctx;
}

// Perform ECDH key exchange
int perform_ecdh(SSL *ssl, unsigned char *shared_secret, size_t *secret_len) {
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(ecdh)) return 0;
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(bio, ecdh);
    char *pubkey;
    long pubkey_len = BIO_get_mem_data(bio, &pubkey);
    char server_pubkey[512];
    int len = SSL_read(ssl, server_pubkey, sizeof(server_pubkey));
    if (len <= 0) return 0;
    SSL_write(ssl, pubkey, pubkey_len);
    BIO *server_bio = BIO_new_mem_buf(server_pubkey, len);
    EC_KEY *server_ecdh = PEM_read_bio_EC_PUBKEY(server_bio, NULL, NULL, NULL);
    *secret_len = ECDH_compute_key(shared_secret, 32, EC_KEY_get0_public_key(server_ecdh), ecdh, NULL);
    BIO_free(bio);
    BIO_free(server_bio);
    EC_KEY_free(ecdh);
    EC_KEY_free(server_ecdh);
    return *secret_len > 0;
}

// Encrypt and send data
int send_encrypted(SSL *ssl, EVP_CIPHER_CTX *ctx, const char *data, unsigned char *hmac_key) {
    unsigned char ciphertext[1024];
    int len, ciphertext_len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)data, strlen(data));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    unsigned char hmac[32];
    HMAC(EVP_sha256(), hmac_key, 32, ciphertext, ciphertext_len, hmac, NULL);
    SSL_write(ssl, ciphertext, ciphertext_len);
    SSL_write(ssl, hmac, 32);
    return ciphertext_len;
}

// Receive and decrypt data
int receive_decrypted(SSL *ssl, EVP_CIPHER_CTX *ctx, char *out, size_t out_len, unsigned char *hmac_key) {
    unsigned char ciphertext[1024], hmac[32], computed_hmac[32];
    int len = SSL_read(ssl, ciphertext, sizeof(ciphertext));
    if (len <= 0) return 0;
    SSL_read(ssl, hmac, 32);
    HMAC(EVP_sha256(), hmac_key, 32, ciphertext, len, computed_hmac, NULL);
    if (memcmp(hmac, computed_hmac, 32) != 0) return 0;
    int out_len_int;
    EVP_DecryptUpdate(ctx, (unsigned char *)out, &out_len_int, ciphertext, len);
    out_len = out_len_int;
    EVP_DecryptFinal_ex(ctx, (unsigned char *)out + out_len, &out_len_int);
    out_len += out_len_int;
    out[out_len] = '\0';
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <username> <host> -p <port> [-password <pass> | -i <keyfile> [command]]\n", argv[0]);
        exit(1);
    }

    char *username = argv[1], *host = argv[2], *port_str = NULL, *password = NULL, *keyfile = NULL, *command = NULL;
    int port = 2222;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-password") == 0 && i + 1 < argc) password = argv[++i];
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) keyfile = argv[++i];
        else if (i == argc - 1) command = argv[i];
    }

    init_openssl();
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_message("Connection failed");
        exit(1);
    }

    SSL_CTX *ctx = create_ssl_context();
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        log_message("SSL connect failed");
        SSL_free(ssl);
        close(sock);
        exit(1);
    }

    // ECDH key exchange
    unsigned char shared_secret[32];
    size_t secret_len;
    if (!perform_ecdh(ssl, shared_secret, &secret_len)) {
        log_message("ECDH key exchange failed");
        SSL_free(ssl);
        close(sock);
        exit(1);
    }

    // Initialize AES context
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_cbc(), NULL, shared_secret, iv);
    EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_cbc(), NULL, shared_secret, iv);

    // Authentication
    char auth_data[512], response[16];
    if (password) {
        snprintf(auth_data, sizeof(auth_data), "%s:password:%s", username, password);
        SSL_write(ssl, auth_data, strlen(auth_data));
    } else if (keyfile) {
        snprintf(auth_data, sizeof(auth_data), "%s:pubkey:ecdsa", username);
        SSL_write(ssl, auth_data, strlen(auth_data));
        FILE *fp = fopen(keyfile, "r");
        if (!fp) {
            log_message("Failed to open keyfile");
            exit(1);
        }
        EC_KEY *ec_key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec_key);
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, "auth_challenge", strlen("auth_challenge"));
        size_t sig_len;
        unsigned char signature[512];
        EVP_DigestSignFinal(md_ctx, signature, &sig_len);
        SSL_write(ssl, signature, sig_len);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
    }
    SSL_read(ssl, response, sizeof(response));
    if (strncmp(response, "AUTH_OK", 7) != 0) {
        log_message("Authentication failed");
        SSL_free(ssl);
        close(sock);
        exit(1);
    }

    // Command execution
    char output[1024];
    if (command) {
        send_encrypted(ssl, ctx_enc, command, shared_secret);
        receive_decrypted(ssl, ctx_dec, output, sizeof(output), shared_secret);
        printf("%s\n", output);
    } else {
        char input[512];
        while (1) {
            printf("ssh> ");
            if (!fgets(input, sizeof(input), stdin)) break;
            input[strcspn(input, "\n")] = '\0';
            if (strcmp(input, "exit") == 0) {
                send_encrypted(ssl, ctx_enc, "exit", shared_secret);
                break;
            }
            send_encrypted(ssl, ctx_enc, input, shared_secret);
            if (receive_decrypted(ssl, ctx_dec, output, sizeof(output), shared_secret)) {
                printf("%s\n", output);
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
