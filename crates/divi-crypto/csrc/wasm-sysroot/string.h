/* SPDX-License-Identifier: AGPL-3.0-only
 * wasm32-unknown-unknown has no libc. The sph hashes need only these two, which
 * Rust's compiler-builtins provides on that target. */
#ifndef DIVI_WASM_STRING_H
#define DIVI_WASM_STRING_H
#include <stddef.h>
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
#endif
