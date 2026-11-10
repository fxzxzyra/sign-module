/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Module signature handling.
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_MODULE_SIGNATURE_H
#define _LINUX_MODULE_SIGNATURE_H

#include <stdint.h>

#define MODULE_SIG_STRING "~Module signature appended~\n"
#define PKEY_ID_PKCS7 2

/* Signature bytes, this header, then MODULE_SIG_STRING. */
struct module_signature {
    uint8_t algo;
    uint8_t hash;
    uint8_t id_type;
    uint8_t signer_len;
    uint8_t key_id_len;
    uint8_t __pad[3];
    uint32_t sig_len;
};

static_assert(sizeof(struct module_signature) == 12, "Kernel signature header must be 12 bytes");

#endif /* _LINUX_MODULE_SIGNATURE_H */
