#ifndef QSAFE_KEYCHAIN_H
#define QSAFE_KEYCHAIN_H

/* OS keychain backing for the secret-key passphrase. On macOS this uses the
 * Keychain (Secure-Enclave-protected on supported hardware) via the Security
 * framework. Other platforms return KC_ERR_UNSUPPORTED until a backend
 * (libsecret on Linux, DPAPI/Credential Manager on Windows) is added. */

#include <stddef.h>

typedef enum {
    KC_OK = 0,
    KC_ERR_UNSUPPORTED = 1,  /* no keychain backend on this platform */
    KC_ERR_NOTFOUND = 2,     /* no item for (service, account) */
    KC_ERR_FAIL = 3
} kc_status;

/* 1 if a keychain backend is compiled in, else 0. */
int keychain_available(void);

/* Store `secret` (a NUL-terminated string) under (service, account),
 * replacing any existing item. */
kc_status keychain_store(const char *service, const char *account, const char *secret);

/* Copy the stored secret into out (NUL-terminated). */
kc_status keychain_retrieve(const char *service, const char *account, char *out, size_t outsz);

/* Remove the item, if present. */
kc_status keychain_delete(const char *service, const char *account);

#endif /* QSAFE_KEYCHAIN_H */
