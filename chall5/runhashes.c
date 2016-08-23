/**
 * Test every password from a file with file2's custom MD5-like hash function
 *
 * Usage:
 *     clang -O2 -Wall -m32 runhashes.c -o runhashes.bin
 *     ./runhashes.bin < password_list
 *
 * With JTR:
 *     john --wordlist=john.txt --rules --stdout | ./runhashes.bin
 */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

int main(void)
{
    int fd = open("file2_clear.out", O_RDONLY);
    assert(fd >= 0);

    uint8_t *mem = mmap(NULL, 208896, PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, 0);
    assert(mem != MAP_FAILED);

    /* call .text:080754FD function (performs hash and compare)
     * ELF program header:
     *     LOAD off    0x00000074 vaddr 0x08048074 paddr 0x08048074 align 2**4
     *          filesz 0x00032e1c memsz 0x00032e1c flags rw
     * => offset 0x080754FD-0x08048000 = 0x2d4fd
     */
    void *fct_hash_and_test = mem + 0x2d4fd;
    char password[4096];
    int cnt = 0;
    while (fgets(password, sizeof(password), stdin)) {
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n')
            password[len - 1] = 0;

        uint32_t result;
        __asm__ volatile(
            "call *%[fct]"
            : [res] "=D" (result) /* result is in edi */
            : [fct] "r" (fct_hash_and_test), [pass] "S" (password)
            : "memory", "cc", "%eax", "%ebx", "%edx"
        );
        if (result) {
            printf("success! %s\n", password);
            return 0;
        }
        cnt ++;
        if (cnt % 100000 == 0) {
            printf("(%d) failed %s\n", cnt, password);
        }
    }
    return 1;
}
