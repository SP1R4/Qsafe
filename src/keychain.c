/* OS keychain backing for the secret-key passphrase.
 *
 * macOS: a generic-password item via the Security framework. Keychain items are
 * protected by the user's login keychain and, on supported hardware, the Secure
 * Enclave — so the wrapping passphrase never has to be typed or stored in the
 * clear.
 *
 * Windows: DPAPI (CryptProtectData) with the service/account pair as extra
 * entropy; the sealed blob lives under %APPDATA%\qsafe\. DPAPI keys are
 * derived from the user's logon credential, so only the same Windows user can
 * unprotect it.
 *
 * Other platforms compile to an "unsupported" stub (libsecret is the natural
 * Linux backend; contributions welcome). */

#include "keychain.h"

#include <string.h>

#ifdef __APPLE__

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

int keychain_available(void) { return 1; }

/* Build the query dictionary identifying one generic-password item. */
static CFMutableDictionaryRef base_query(const char *service, const char *account) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!q) return NULL;
    CFDictionaryAddValue(q, kSecClass, kSecClassGenericPassword);
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFDictionaryAddValue(q, kSecAttrService, svc);
    CFDictionaryAddValue(q, kSecAttrAccount, acc);
    CFRelease(svc);
    CFRelease(acc);
    return q;
}

kc_status keychain_store(const char *service, const char *account, const char *secret) {
    if (!service || !account || !secret) return KC_ERR_FAIL;
    /* Replace any existing item: delete then add (simpler than SecItemUpdate). */
    keychain_delete(service, account);
    CFMutableDictionaryRef q = base_query(service, account);
    if (!q) return KC_ERR_FAIL;
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)secret, (CFIndex)strlen(secret));
    CFDictionaryAddValue(q, kSecValueData, data);
    /* Require the keychain to be unlocked (device unlocked) for access. */
    CFDictionaryAddValue(q, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked);
    OSStatus rc = SecItemAdd(q, NULL);
    CFRelease(data);
    CFRelease(q);
    return rc == errSecSuccess ? KC_OK : KC_ERR_FAIL;
}

kc_status keychain_retrieve(const char *service, const char *account, char *out, size_t outsz) {
    if (!service || !account || !out || outsz == 0) return KC_ERR_FAIL;
    CFMutableDictionaryRef q = base_query(service, account);
    if (!q) return KC_ERR_FAIL;
    CFDictionaryAddValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionaryAddValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus rc = SecItemCopyMatching(q, &result);
    CFRelease(q);
    if (rc == errSecItemNotFound) return KC_ERR_NOTFOUND;
    if (rc != errSecSuccess || !result) return KC_ERR_FAIL;
    CFDataRef data = (CFDataRef)result;
    CFIndex len = CFDataGetLength(data);
    kc_status st = KC_ERR_FAIL;
    if (len >= 0 && (size_t)len < outsz) {
        memcpy(out, CFDataGetBytePtr(data), (size_t)len);
        out[len] = '\0';
        st = KC_OK;
    }
    CFRelease(result);
    return st;
}

kc_status keychain_delete(const char *service, const char *account) {
    CFMutableDictionaryRef q = base_query(service, account);
    if (!q) return KC_ERR_FAIL;
    OSStatus rc = SecItemDelete(q);
    CFRelease(q);
    if (rc == errSecSuccess) return KC_OK;
    if (rc == errSecItemNotFound) return KC_ERR_NOTFOUND;
    return KC_ERR_FAIL;
}

#elif defined(_WIN32)

#include <windows.h>
#include <wincrypt.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

int keychain_available(void) { return 1; }

/* Resolves the sealed-blob path for one (service, account) item:
 * %APPDATA%\qsafe\kc_<sha256(service \0 account)>.bin. The hash keeps the
 * account (a key-file path) out of the filename. Returns 1 on success. */
static int item_path(const char *service, const char *account, char *buf, size_t n) {
    const char *base = getenv("APPDATA");
    if (!base || !*base) return 0;

    unsigned char digest[32];
    unsigned int dl = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = md &&
             EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(md, service, strlen(service) + 1) == 1 &&
             EVP_DigestUpdate(md, account, strlen(account)) == 1 &&
             EVP_DigestFinal_ex(md, digest, &dl) == 1 && dl == 32;
    if (md) EVP_MD_CTX_free(md);
    if (!ok) return 0;

    char dir[1024];
    if ((size_t)snprintf(dir, sizeof(dir), "%s\\qsafe", base) >= sizeof(dir)) return 0;
    _mkdir(dir); /* best effort; exists is fine */

    char hex[65];
    static const char hexc[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[2 * i] = hexc[digest[i] >> 4];
        hex[2 * i + 1] = hexc[digest[i] & 0xf];
    }
    hex[64] = '\0';
    return (size_t)snprintf(buf, n, "%s\\kc_%s.bin", dir, hex) < n;
}

kc_status keychain_store(const char *service, const char *account, const char *secret) {
    if (!service || !account || !secret) return KC_ERR_FAIL;
    char path[1024], entropy_buf[1024];
    if (!item_path(service, account, path, sizeof(path))) return KC_ERR_FAIL;
    if ((size_t)snprintf(entropy_buf, sizeof(entropy_buf), "%s\n%s", service, account)
        >= sizeof(entropy_buf)) return KC_ERR_FAIL;

    DATA_BLOB in = { (DWORD)strlen(secret), (BYTE *)secret };
    DATA_BLOB entropy = { (DWORD)strlen(entropy_buf), (BYTE *)entropy_buf };
    DATA_BLOB out = { 0, NULL };
    if (!CryptProtectData(&in, L"qsafe keychain passphrase", &entropy, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return KC_ERR_FAIL;
    }

    kc_status st = KC_ERR_FAIL;
    FILE *f = fopen(path, "wb");
    if (f) {
        if (fwrite(out.pbData, 1, out.cbData, f) == out.cbData) st = KC_OK;
        fclose(f);
        if (st != KC_OK) remove(path);
    }
    LocalFree(out.pbData);
    return st;
}

kc_status keychain_retrieve(const char *service, const char *account, char *out, size_t outsz) {
    if (!service || !account || !out || outsz == 0) return KC_ERR_FAIL;
    char path[1024], entropy_buf[1024];
    if (!item_path(service, account, path, sizeof(path))) return KC_ERR_FAIL;
    if ((size_t)snprintf(entropy_buf, sizeof(entropy_buf), "%s\n%s", service, account)
        >= sizeof(entropy_buf)) return KC_ERR_FAIL;

    FILE *f = fopen(path, "rb");
    if (!f) return KC_ERR_NOTFOUND;
    unsigned char blob[4096];
    size_t blen = fread(blob, 1, sizeof(blob), f);
    int overlong = (fgetc(f) != EOF);
    fclose(f);
    if (blen == 0 || overlong) return KC_ERR_FAIL;

    DATA_BLOB in = { (DWORD)blen, blob };
    DATA_BLOB entropy = { (DWORD)strlen(entropy_buf), (BYTE *)entropy_buf };
    DATA_BLOB dec = { 0, NULL };
    if (!CryptUnprotectData(&in, NULL, &entropy, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &dec)) {
        return KC_ERR_FAIL;
    }
    kc_status st = KC_ERR_FAIL;
    if ((size_t)dec.cbData < outsz) {
        memcpy(out, dec.pbData, dec.cbData);
        out[dec.cbData] = '\0';
        st = KC_OK;
    }
    OPENSSL_cleanse(dec.pbData, dec.cbData);
    LocalFree(dec.pbData);
    return st;
}

kc_status keychain_delete(const char *service, const char *account) {
    char path[1024];
    if (!item_path(service, account, path, sizeof(path))) return KC_ERR_FAIL;
    if (remove(path) == 0) return KC_OK;
    return KC_ERR_NOTFOUND;
}

#else  /* no backend yet (Linux: libsecret would go here) */

int keychain_available(void) { return 0; }

kc_status keychain_store(const char *service, const char *account, const char *secret) {
    (void)service; (void)account; (void)secret;
    return KC_ERR_UNSUPPORTED;
}

kc_status keychain_retrieve(const char *service, const char *account, char *out, size_t outsz) {
    (void)service; (void)account; (void)out; (void)outsz;
    return KC_ERR_UNSUPPORTED;
}

kc_status keychain_delete(const char *service, const char *account) {
    (void)service; (void)account;
    return KC_ERR_UNSUPPORTED;
}

#endif
