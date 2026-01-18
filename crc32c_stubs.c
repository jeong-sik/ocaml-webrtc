/* CRC32c Hardware-Accelerated Implementation
 *
 * Uses ARM CRC instructions (M1/M2/M3) or x86_64 SSE4.2.
 * Falls back to software implementation if unavailable.
 *
 * RFC 4960 Appendix B - CRC32c for SCTP
 */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <stdint.h>
#include <string.h>

/* Detect hardware support */
#if defined(__aarch64__) || defined(_M_ARM64)
  #define USE_ARM_CRC 1
  #include <arm_acle.h>
#elif defined(__x86_64__) || defined(_M_X64)
  #if defined(__SSE4_2__)
    #define USE_SSE42_CRC 1
    #include <nmmintrin.h>
  #endif
#endif

/* Software fallback table */
static uint32_t crc32c_table[256];
static int table_initialized = 0;

static void init_crc32c_table(void) {
    if (table_initialized) return;

    for (int i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x82F63B78;
            else
                crc >>= 1;
        }
        crc32c_table[i] = crc;
    }
    table_initialized = 1;
}

/* Software CRC32c (fallback) */
static uint32_t crc32c_software(const uint8_t *data, size_t len) {
    init_crc32c_table();
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i]) & 0xFF];
    }

    return crc ^ 0xFFFFFFFF;
}

#ifdef USE_ARM_CRC
/* ARM64 hardware CRC32c using ACLE intrinsics */
static uint32_t crc32c_hardware(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    /* Process 8 bytes at a time */
    while (len >= 8) {
        uint64_t val;
        memcpy(&val, data, 8);
        crc = __crc32cd(crc, val);
        data += 8;
        len -= 8;
    }

    /* Process 4 bytes */
    if (len >= 4) {
        uint32_t val;
        memcpy(&val, data, 4);
        crc = __crc32cw(crc, val);
        data += 4;
        len -= 4;
    }

    /* Process 2 bytes */
    if (len >= 2) {
        uint16_t val;
        memcpy(&val, data, 2);
        crc = __crc32ch(crc, val);
        data += 2;
        len -= 2;
    }

    /* Process remaining byte */
    if (len >= 1) {
        crc = __crc32cb(crc, *data);
    }

    return crc ^ 0xFFFFFFFF;
}
#elif defined(USE_SSE42_CRC)
/* x86_64 SSE4.2 hardware CRC32c */
static uint32_t crc32c_hardware(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    /* Process 8 bytes at a time */
    while (len >= 8) {
        crc = (uint32_t)_mm_crc32_u64(crc, *(uint64_t*)data);
        data += 8;
        len -= 8;
    }

    /* Process 4 bytes */
    if (len >= 4) {
        crc = _mm_crc32_u32(crc, *(uint32_t*)data);
        data += 4;
        len -= 4;
    }

    /* Process remaining bytes */
    while (len > 0) {
        crc = _mm_crc32_u8(crc, *data);
        data++;
        len--;
    }

    return crc ^ 0xFFFFFFFF;
}
#else
/* No hardware support - use software */
#define crc32c_hardware crc32c_software
#endif

/* OCaml binding: crc32c_fast : bytes -> int32 */
CAMLprim value caml_crc32c_fast(value v_data) {
    CAMLparam1(v_data);

    const uint8_t *data = (const uint8_t *)Bytes_val(v_data);
    size_t len = caml_string_length(v_data);

    uint32_t result = crc32c_hardware(data, len);

    CAMLreturn(caml_copy_int32(result));
}

/* Check if hardware acceleration is available */
CAMLprim value caml_crc32c_has_hardware(value unit) {
    CAMLparam1(unit);
#if defined(USE_ARM_CRC) || defined(USE_SSE42_CRC)
    CAMLreturn(Val_true);
#else
    CAMLreturn(Val_false);
#endif
}
