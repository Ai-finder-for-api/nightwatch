#include "qs_crypt/qs_crypt.h"
#include <string.h>

/* Keep qsc enum values, struct layouts and digest sizing on the C side. */
int nw_sha256(const unsigned char *input, size_t n, unsigned char out[32]) {
    qsc_slice_t slice = { input, n };
    qsc_digest_t digest;
    qsc_error_t err = qsc_hash(QSC_ALG_SHA2_256, slice, &digest);
    if (err != QSC_OK) return (int)err;
    if (digest.length != 32) return -1;
    memcpy(out, digest.data, 32);
    return 0;
}
