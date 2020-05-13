#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <errno.h>

#include <openssl/evp.h>

#define FILE_SIZE 1024 * 1024 * 16

int create_file_set_size(char *file_name, unsigned int file_size)
{
    int fd = open(file_name,
                  O_CREAT | O_RDWR,
                  S_IRUSR | S_IWUSR
    );
    if (fd == -1)
    { // errore!
        perror("open()");
        return -1;
    }
    int res = ftruncate(fd, file_size);
    if (res == -1)
    {
        perror("ftruncate()");
        return -1;
    }

    return fd;
}

#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }

unsigned char *sha3_512(char *addr, unsigned int size, int *result_len_ptr)
{

    EVP_MD_CTX *mdctx;
    int val;
    unsigned char *digest;
    unsigned int digest_len;
    EVP_MD *algo = NULL;

    algo = EVP_sha3_512();

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        HANDLE_ERROR("EVP_MD_CTX_create() error")
    }

    // initialize digest engine
    if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1)
    { // returns 1 if successful
        HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
    }

    // provide data to digest engine
    if (EVP_DigestUpdate(mdctx, addr, size) != 1)
    { // returns 1 if successful
        HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
    }

    digest_len = EVP_MD_size(algo); // sha3_512 returns a 512 bit hash

    if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL)
    {
        HANDLE_ERROR2("OPENSSL_malloc() error", mdctx)
    }

    // produce digest
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1)
    { // returns 1 if successful
        OPENSSL_free(digest);
        HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
    }

    char *result = malloc(digest_len);
    if (result == NULL)
    {
        perror("malloc()");
        exit(EXIT_FAILURE);
    }

    memcpy(result, digest, digest_len);

    *result_len_ptr = digest_len;

    OPENSSL_free(digest);
    EVP_MD_CTX_destroy(mdctx);

    return result;
}

int main(int argc, char * argv[]) {
    char *file_name ;
    unsigned int file_size = FILE_SIZE;
    int fd;
    int res;
    char *addr;
    if (argc > 1)
    {
        file_name = argv[1];

        if (argc > 2)
        {
            unsigned int temp;
            res = sscanf(argv[2], "%u", &temp);
            if (res == 1)
                file_size = temp;
        }
    }
    fd = create_file_set_size(file_name, file_size);
    if (fd == -1)
    {
        exit(EXIT_FAILURE);
    }
    // creo mmap condivisa
    addr = mmap(NULL,                   // NULL: è il kernel a scegliere l'indirizzo
                file_size,              // dimensione della memory map
                PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
                MAP_SHARED,             // memory map condivisibile con altri processi
                fd,
                0); // offset nel file

    if (addr == MAP_FAILED)
    {
        perror("mmap()");
        exit(EXIT_FAILURE);
    }
    close(fd);
    // creo pipe
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1)
    {
        perror("pipe()");

        exit(EXIT_FAILURE);
    }
    unsigned char *digest;
    int digest_len;
    switch(fork())
    {
        case -1:
            perror("problema con fork");
            exit(EXIT_FAILURE);

        case 0:
            close(pipe_fd[1]);
            char * tofill = malloc(file_size * sizeof(char));
            while ((res = read(pipe_fd[0], tofill, file_size)) > 0)
            {
                printf("[child] received %d bytes from pipe\n", res);
            }
            if (res == -1)
            {
                perror("read()");
            }
            else
            {
                printf("[child] EOF on pipe\n");
            }
            digest = sha3_512(tofill, file_size, &digest_len);
            memcpy(addr, digest, digest_len);
            printf("[child] SHA3_512 on %u bytes: ", file_size);
            for (int i = 0; i < digest_len; i++)
            {
                printf("%02x", digest[i]);
            }
            printf("\n[child] bye\n");
            close(pipe_fd[0]);

            exit(EXIT_SUCCESS);

        default:
            printf("[parent] starting\n");
            close(pipe_fd[0]);
            res = write(pipe_fd[1], addr, file_size);
            if (res == -1)
            {
                perror("write()");
            }
            printf("[parent] %d bytes written to pipe\n", res);
            close(pipe_fd[1]);
            printf("[parent] before wait()\n");
            wait(NULL);
            printf("[parent] SHA3_512 from child process: ");
            for (int i = 0; i < 512 / 8; i++)
            {
                printf("%02x", addr[i] & 0xFF);
            }
            printf("\n[parent] bye\n");
            exit(EXIT_SUCCESS);
    }

    return 0;
}


