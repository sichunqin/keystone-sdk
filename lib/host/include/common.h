#ifndef __COMMON_H__
#define __COMMON_H__

#define PAGE_BITS 12
#define PAGE_SIZE (1UL<<PAGE_BITS)
#define ROUND_UP(n, b) (((((n) - 1ul) >> (b)) + 1ul) << (b))
#define ROUND_DOWN(n, b) (n & ~((2 << (b-1)) - 1))

#define BOOST_STRINGIZE(X) BOOST_DO_STRINGIZE(X)
#define BOOST_DO_STRINGIZE(X) #X

#define KEYSTONE_DEV_PATH "/dev/keystone_enclave"

#define MSG(str) "[Keystone SDK] " __FILE__ ":" BOOST_STRINGIZE(__LINE__) " : " str
#define ERROR(str, ...) fprintf(stderr, MSG(str) "\n", ##__VA_ARGS__)
#define PERROR(str) perror(MSG(str))
#define IS_ALIGNED(x, align) (!((x)&(align-1)))

/* Types */
typedef uintptr_t vaddr_t;
typedef uintptr_t paddr_t;

typedef enum {
  KEYSTONE_ERROR=-1,
  KEYSTONE_SUCCESS,
  KEYSTONE_NOT_IMPLEMENTED,
} keystone_status_t;


#endif
