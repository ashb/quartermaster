#import "QuartermasterIPC.h"
#include <stdint.h>

typedef void (*QMContextHandler)(void *, uint64_t, uint32_t, const uint8_t *, size_t, uint64_t, void *, void *, void *);
int qm_context_serve(const char *, const char *, void *, QMContextHandler);
void qm_context_reply(void *, const uint8_t *, size_t);
void qm_context_expire(void *, uint64_t, uint64_t);
void qm_context_release_lease(uint64_t, uint64_t);
bool qm_context_connected(void *);
