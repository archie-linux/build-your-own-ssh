#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/wait.h>

// Logging function
void log_message(const char *msg) {
    FILE *log = fopen("ssh_server.log", "a");
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

// Load TLS context
SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_message("Unable to create SSL context");
        exit(1);
    }
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        log_message("Error loading TLS certificates");
        exit(1);
    }
    return ctx;
}

// Load user database (format: username:sha256_password:pubkey_file)
int load_user(const char *username, char *stored_hash, char *pubkey_file) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) return 0;
    char line[512], file_user[64], file_hash[65], file_pubkey[256];
    while (fgets(line, sizeof(line), fp)) {
        sscanf(line, "%[^:]:%[^:]:%s", file_user, file_hash, file_pubkey);
        if (strcmp(file_user, username) == 0) {
            strcpy(stored_hash, file_hash);
            strcpy(pubkey_file, file_pubkey);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

// Verify password
int verify_password(const char *password, const char *stored_hash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), hash);
    char hash_str[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    hash_str[64] = '\0';
    return strcmp(hash_str, stored_hash) == 0;
}

// Verify public key (simplified ECDSA check)
int verify_pubkey(const char *pubkey_file, const char *data, const char *signature, size_t sig_len) {
    FILE *fp = fopen(pubkey_file, "r");
    if (!fp) return 0;
    EC_KEY *ec_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ec_key) return 0;
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestVerifyUpdate(md_ctx, data, strlen(data));
    int result = EVP_DigestVerifyFinal(md_ctx, (unsigned char *)signature, sig_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return result == 1;
}

// Perform ECDH key exchange
int perform_ecdh(SSL *ssl, unsigned char *shared_secret, size_t *secret_len) {
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(ecdh)) return 0;
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(bio, ecdh);
    char *pubkey;
    long pubkey_len = BIO_get_mem_data(bio, &pubkey);
    SSL_write(ssl, pubkey, pubkey_len);
    char client_pubkey[512];
    int len = SSL_read(ssl, client_pubkey, sizeof(client_pubkey));
    if (len <= 0) return 0;
    BIO *client_bio = BIO_new_mem_buf(client_pubkey, len);
    EC_KEY *client_ecdh = PEM_read_bio_EC_PUBKEY(client_bio, NULL, NULL, NULL);
    *secret_len = ECDH_compute_key(shared_secret, 32, EC_KEY_get0_public_key(client_ecdh), ecdh, NULL);
    BIO_free(bio);
    BIO_free(client_bio);
    EC_KEY_free(ecdh);
    EC_KEY_free(client_ecdh);
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

// Execute command and return output
void execute_command(const char *cmd, char *output, size_t out_len) {
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        snprintf(output, out_len, "Command execution failed");
        return;
    }
    fread(output, 1, out_len - 1, fp);
    output[out_len - 1] = '\0';
    pclose(fp);
}

int main() {
    init_openssl();
    int server_fd, client_fd;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2222);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_message("Socket creation failed");
        exit(1);
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(server_fd, 10) < 0) {
        log_message("Bind or listen failed");
        exit(1);
    }

    SSL_CTX *ctx = create_ssl_context();
    log_message("Server started on localhost:2222");

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            log_message("SSL accept failed");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        // ECDH key exchange
        unsigned char shared_secret[32];
        size_t secret_len;
        if (!perform_ecdh(ssl, shared_secret, &secret_len)) {
            log_message("ECDH key exchange failed");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        // Initialize AES context
        EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
        unsigned char iv[16] = {0};
        EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_cbc(), NULL, shared_secret, iv);
        EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_cbc(), NULL, shared_secret, iv);

        // Authentication
        char username[64], auth_type[16], auth_data[512], signature[512];
        int auth_data_len = SSL_read(ssl, auth_data, sizeof(auth_data));
        sscanf(auth_data, "%[^:]:%[^:]:%s", username, auth_type, auth_data);
        char stored_hash[65], pubkey_file[256];
        int auth_success = 0;
        if (!load_user(username, stored_hash, pubkey_file)) {
            log_message("User not found");
            SSL_write(ssl, "AUTH_FAIL", 9);
        } else if (strcmp(auth_type, "password") == 0) {
            auth_success = verify_password(auth_data, stored_hash);
        } else if (strcmp(auth_type, "pubkey") == 0) {
            int sig_len = SSL_read(ssl, signature, sizeof(signature));
            auth_success = verify_pubkey(pubkey_file, "auth_challenge", signature, sig_len);
        }
        SSL_write(ssl, auth_success ? "AUTH_OK" : "AUTH_FAIL", 9);
        if (!auth_success) {
            log_message("Authentication failed");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        // Command loop
        char command[512], output[1024];
        while (1) {
            if (!receive_decrypted(ssl, ctx_dec, command, sizeof(command), shared_secret)) {
                log_message("Failed to receive command");
                break;
            }
            if (strcmp(command, "exit") == 0) break;
            execute_command(command, output, sizeof(output));
            send_encrypted(ssl, ctx_enc, output, shared_secret);
        }

        EVP_CIPHER_CTX_free(ctx_enc);
        EVP_CIPHER_CTX_free(ctx_dec);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
