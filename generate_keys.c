#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>

// Generate ECDSA key pair
void generate_ecdsa_key(const char *pubkey_file, const char *privkey_file) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec_key);
    FILE *fp = fopen(pubkey_file, "w");
    PEM_write_EC_PUBKEY(fp, ec_key);
    fclose(fp);
    fp = fopen(privkey_file, "w");
    PEM_write_ECPrivateKey(fp, ec_key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    EC_KEY_free(ec_key);
}

// Generate self-signed TLS certificate
void generate_tls_cert() {
    X509 *x509 = X509_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(ec_key);
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_set_pubkey(x509, pkey);

    X509_sign(x509, pkey, EVP_sha256());
    FILE *fp = fopen("server.crt", "w");
    PEM_write_X509(fp, x509);
    fclose(fp);
    fp = fopen("server.key", "w");
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    X509_free(x509);
    EVP_PKEY_free(pkey);
}

int main() {
    generate_ecdsa_key("user.pub", "user.key");
    generate_tls_cert();
    FILE *fp = fopen("users.txt", "w");
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)"mysecurepass", strlen("mysecurepass"), hash);
    char hash_str[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    hash_str[64] = '\0';
    fprintf(fp, "user:%s:user.pub\n", hash_str);
    fclose(fp);
    printf("Generated keys, certificate, and user database\n");
    return 0;
}
