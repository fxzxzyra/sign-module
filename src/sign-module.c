/* Kernel module signing with OpenSSL 4.x and XZ support. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <lzma.h>

#include <linux/module_signature.h>

static const char magic_number[] = MODULE_SIG_STRING;

static void fatal(const char *fmt, ...)
    __attribute__((noreturn, format(printf, 1, 2)));

static void fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static void *resize(void *data, size_t size)
{
    void *out = realloc(data, size ? size : 1);

    if (!out)
        fatal("Out of memory\n");

    return out;
}

static unsigned char *read_file(const char *path, size_t *size)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0 || fstat(fd, &st) < 0)
        fatal("open/stat(%s): %s\n", path, strerror(errno));
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > INT_MAX)
        fatal("Module must be a regular file smaller than 2 GiB\n");

    *size = (size_t)st.st_size;
    unsigned char *data = resize(NULL, *size);

    for (size_t used = 0; used < *size;) {
        ssize_t n = read(fd, data + used, *size - used);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            fatal("read(%s): %s\n", path, n < 0 ? strerror(errno) : "unexpected end of file");

        used += (size_t)n;
    }

    close(fd);
    return data;
}

static bool is_xz(const unsigned char *data, size_t size)
{
    return size >= 6 && memcmp(data, "\xfd" "7zXZ\0", 6) == 0;
}

static size_t unsigned_size(const unsigned char *data, size_t size)
{
    const size_t trailer = sizeof(struct module_signature) + sizeof(magic_number) - 1;

    while (size >= trailer &&
           memcmp(data + size - sizeof(magic_number) + 1, magic_number,
                  sizeof(magic_number) - 1) == 0) {
        struct module_signature sig;

        memcpy(&sig, data + size - trailer, sizeof(sig));

        if (sig.id_type != PKEY_ID_PKCS7 || ntohl(sig.sig_len) > size - trailer)
            fatal("Invalid module signature trailer\n");

        size -= trailer + ntohl(sig.sig_len);
    }

    return size;
}

/* Consume the input buffer and share one coding loop for both directions. */
static unsigned char *xz_transform(unsigned char *data, size_t *size, bool compress)
{
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_options_lzma options;

    lzma_lzma_preset(&options, LZMA_PRESET_DEFAULT);
    options.dict_size = 1U << 20;

    const lzma_filter filters[] = {
        {
            .id = LZMA_FILTER_LZMA2,
            .options = &options
        },
        {
            .id = LZMA_VLI_UNKNOWN
        }
    };
    lzma_mt mt = {
        .threads = lzma_cputhreads(),
        .filters = filters,
        .check = LZMA_CHECK_CRC32,
        .flags = compress ? 0 : LZMA_CONCATENATED,
        .memlimit_threading = 256U << 20,
        .memlimit_stop = UINT64_MAX
    };

    if (!mt.threads)
        mt.threads = 1;

    if (compress) {
        /* Avoid idle workers for small modules and cap encoder working memory. */
        mt.block_size = 3U << 20;
        while (mt.threads > 1 &&
               ((uint64_t)(mt.threads - 1) * mt.block_size >= *size ||
                lzma_stream_encoder_mt_memusage(&mt) > (256U << 20)))
            --mt.threads;
    }

    lzma_ret ret = compress ? lzma_stream_encoder_mt(&stream, &mt)
                            : lzma_stream_decoder_mt(&stream, &mt);
    if (ret != LZMA_OK)
        fatal("XZ initialization failed: %d\n", (int)ret);

    size_t capacity = *size > 4096 ? *size : 4096;
    unsigned char *out = resize(NULL, capacity);

    stream.next_in = data;
    stream.avail_in = *size;
    stream.next_out = out;
    stream.avail_out = capacity;

    while ((ret = lzma_code(&stream, LZMA_FINISH)) != LZMA_STREAM_END) {
        if (ret != LZMA_OK)
            fatal("XZ %s failed: %d\n",
                  compress ? "compression" : "decompression", (int)ret);

        if (stream.avail_out == 0) {
            if (capacity > INT_MAX / 2)
                fatal("Module exceeds the 2 GiB processing limit\n");

            out = resize(out, capacity * 2);
            stream.next_out = out + capacity;
            stream.avail_out = capacity;
            capacity *= 2;
        }
    }

    *size = stream.total_out;
    lzma_end(&stream);
    free(data);
    return out;
}

static X509 *load_cert(const char *path)
{
    BIO *bio = BIO_new_file(path, "rb");

    if (!bio)
        fatal("open certificate %s\n", path);

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        ERR_clear_error();
        if (BIO_reset(bio) != 0)
            fatal("rewind certificate %s\n", path);
        cert = d2i_X509_bio(bio, NULL);
    }

    BIO_free(bio);
    if (!cert)
        fatal("parse certificate %s\n", path);

    return cert;
}

static EVP_PKEY *load_key(const char *path)
{
    BIO *bio = BIO_new_file(path, "rb");

    if (!bio)
        fatal("open key %s\n", path);

    EVP_PKEY *key = PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, NULL, NULL, NULL);
    BIO_free(bio);

    if (!key)
        fatal("parse key %s\n", path);

    return key;
}

/* Append DER directly to the module allocation; the kernel forbids signed attributes. */
static unsigned char *sign_module(unsigned char *data, size_t *size,
                                  const char *hash, EVP_PKEY *key, X509 *cert)
{
    *size = unsigned_size(data, *size);

    EVP_MD *md = EVP_MD_fetch(NULL, hash, NULL);
    if (!md)
        fatal("Unavailable digest '%s'\n", hash);

    CMS_ContentInfo *cms = CMS_sign_ex(
        NULL, NULL, NULL, NULL,
        CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED, NULL, NULL);
    if (!cms || !CMS_add1_signer(cms, cert, key, md, CMS_NOCERTS | CMS_NOATTR))
        fatal("Create CMS signer failed\n");

    BIO *content = BIO_new_mem_buf(data, (int)*size);
    if (!content || CMS_final(cms, content, NULL, CMS_BINARY | CMS_DETACHED) != 1)
        fatal("Finalize CMS signature failed\n");

    BIO_free(content);
    EVP_MD_free(md);

    int der_size = i2d_CMS_ContentInfo(cms, NULL);
    if (der_size <= 0)
        fatal("Encode CMS signature failed\n");

    data = resize(data, *size + (size_t)der_size +
                        sizeof(struct module_signature) + sizeof(magic_number) - 1);
    unsigned char *tail = data + *size;

    if (i2d_CMS_ContentInfo(cms, &tail) != der_size)
        fatal("Encode CMS signature failed\n");

    CMS_ContentInfo_free(cms);

    memcpy(tail,
           &(struct module_signature){
               .id_type = PKEY_ID_PKCS7,
               .sig_len = htonl((uint32_t)der_size)
           },
           sizeof(struct module_signature));
    memcpy(tail + sizeof(struct module_signature), magic_number, sizeof(magic_number) - 1);
    *size += (size_t)der_size + sizeof(struct module_signature) + sizeof(magic_number) - 1;

    return data;
}

/* Write the completed buffer directly to the original file. */
static void write_file(const char *path, const unsigned char *data, size_t size)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);

    if (fd < 0)
        fatal("open(%s): %s\n", path, strerror(errno));

    for (size_t used = 0; used < size;) {
        ssize_t n = write(fd, data + used, size - used);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            fatal("write(%s): %s\n", path, n < 0 ? strerror(errno) : "no progress");

        used += (size_t)n;
    }

    if (close(fd) < 0)
        fatal("close(%s): %s\n", path, strerror(errno));
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <hash> <private_key.pem> <x509.der|.pem> <module.ko[.xz]>\n",
                argv[0]);
        return 2;
    }

    EVP_PKEY *key = load_key(argv[2]);
    X509 *cert = load_cert(argv[3]);

    size_t size;
    unsigned char *data = read_file(argv[4], &size);
    bool compressed = is_xz(data, size);

    if (compressed)
        data = xz_transform(data, &size, false);

    data = sign_module(data, &size, argv[1], key, cert);

    if (compressed)
        data = xz_transform(data, &size, true);

    write_file(argv[4], data, size);
    free(data);
    X509_free(cert);
    EVP_PKEY_free(key);

    return 0;
}
