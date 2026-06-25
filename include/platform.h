#ifndef QSAFE_PLATFORM_H
#define QSAFE_PLATFORM_H

/* Small cross-platform shim. Qsafe targets POSIX (Linux/macOS) and Windows via
 * MinGW-w64/MSYS2. The genuinely platform-different operations live here so the
 * rest of the code stays clean. */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>   /* realpath (POSIX) / _fullpath (Windows) */
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
  #include <windows.h>
  #include <io.h>
  #include <fcntl.h>
  #include <direct.h>
  #include <sys/utime.h>
  #ifndef PATH_MAX
    #define PATH_MAX MAX_PATH
  #endif
#else
  #include <limits.h>
  #include <unistd.h>
  #include <utime.h>
#endif

/* Put stdin/stdout into binary mode. On Windows the C runtime otherwise
 * translates LF<->CRLF on these streams, which silently corrupts piped
 * ciphertext/plaintext. No-op on POSIX. Call once at startup. */
static inline void qsafe_set_binary_stdio(void) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
}

/* Create a directory with default permissions. Returns 0 on success. */
static inline int qsafe_mkdir(const char *path) {
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

/* Restrict a file to its owner (the 0600 intent for secret-key material).
 * Best-effort on Windows, which has no POSIX permission bits. */
static inline void qsafe_chmod_private(const char *path) {
#ifdef _WIN32
    _chmod(path, _S_IREAD | _S_IWRITE);
#else
    chmod(path, 0600);
#endif
}

/* Best-effort restore of a decrypted file's permission bits and mtime. On
 * Windows only the mtime is applied (no POSIX mode bits). */
static inline void qsafe_restore_meta(const char *path, unsigned mode, unsigned long long mtime) {
#ifdef _WIN32
    (void)mode;
    struct _utimbuf t;
    t.actime = (time_t)mtime;
    t.modtime = (time_t)mtime;
    _utime(path, &t);
#else
    chmod(path, (mode_t)(mode & 0777));
    struct utimbuf t;
    t.actime = (time_t)mtime;
    t.modtime = (time_t)mtime;
    utime(path, &t);
#endif
}

/* Canonicalize `path` into `resolved` (which must hold at least PATH_MAX bytes).
 * Returns 1 on success, 0 on failure. */
static inline int qsafe_realpath(const char *path, char *resolved) {
#ifdef _WIN32
    return _fullpath(resolved, path, PATH_MAX) != NULL;
#else
    return realpath(path, resolved) != NULL;
#endif
}

#endif /* QSAFE_PLATFORM_H */
