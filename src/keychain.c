/* OS keychain backing for the secret-key passphrase.
 *
 * macOS: a generic-password item via the Security framework. Keychain items are
 * protected by the user's login keychain and, on supported hardware, the Secure
 * Enclave — so the wrapping passphrase never has to be typed or stored in the
 * clear. Other platforms compile to an "unsupported" stub. */

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

#else  /* non-Apple: no backend yet */

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
