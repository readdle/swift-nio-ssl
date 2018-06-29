//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
// Note that we don't include our umbrella header because it declares a bunch of
// static inline functions that will cause havoc if they end up in multiple
// compilation units.
//
// At some point we should probably just make them all live in this .o file, as the
// cost of the function call is in practice very small.
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <pthread.h>

/// This will store the locks we're using for the locking callbacks.
static pthread_mutex_t *locks = NULL;
static int lockCount = 0;


/// Our locking callback. It lives only in this compilation unit.
static void CNIOOpenSSL_locking_callback(int mode, int lockIndex, const char *file, int line) {
    if (lockIndex >= lockCount) {
        fprintf(stderr, "Invalid lock index %d, only have %d locks\n", lockIndex, lockCount);
        abort();
    }

    int rc;
    if (mode & CRYPTO_LOCK) {
        rc = pthread_mutex_lock(&locks[lockIndex]);
    } else {
        rc = pthread_mutex_unlock(&locks[lockIndex]);
    }

    if (rc != 0) {
        fprintf(stderr, "Failed to operate mutex: error %d, mode %d", rc, mode);
        abort();
    }
}


/// Our thread-id callback. Again, only in this compilation unit.
static unsigned long CNIOOpenSSL_thread_id_function(void) {
    return (unsigned long)pthread_self();
}


/// Initialize the locking callbacks.
static void CNIOOpenSSL_InitializeLockingCallbacks(void) {
    // The locking callbacks are only necessary on OpenSSL earlier than 1.1, or
    // libre.
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
    // Don't double-set the locking callbacks.
    if (CRYPTO_get_locking_callback() != NULL) {
        return;
    }

    lockCount = CRYPTO_num_locks();
    locks = malloc(lockCount * sizeof(typeof(locks[0])));

    for (int i = 0; i < lockCount; i++) {
        pthread_mutex_init(&locks[i], NULL);
    }

    CRYPTO_set_id_callback(CNIOOpenSSL_thread_id_function);
    CRYPTO_set_locking_callback(CNIOOpenSSL_locking_callback);
#endif
    return;
}

/// Initialize OpenSSL.
void CNIOOpenSSL_InitializeOpenSSL(void) {
    SSL_library_init();
    OPENSSL_add_all_algorithms_conf();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    CNIOOpenSSL_InitializeLockingCallbacks();
}
