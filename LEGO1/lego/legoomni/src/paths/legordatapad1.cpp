#include "legopathboundary.h"

// .rdata SIZE CARRIER (1 of 4).
//
// Our .rdata is 96 bytes shorter than retail's, and every contribution from
// .rdata offset 0x9200 onward -- roughly 74 KB, the whole COMDAT tail -- is
// byte-identical to retail's but sits exactly 96 bytes too low. Restoring the
// section to retail's VirtualSize re-seats that tail and, with it, every
// absolute reference into it from .text and .data.
//
// Each of these four units contributes only the file-scope constant pool that
// tglvector.h places in .rdata (20 bytes, padded to 24): no code, no data, no
// COMDAT, and therefore no effect on any other translation unit's compile
// state. Measured at 9cb31d55 (build-identical, retail-vs-ours per section):
//
//     .rdata VirtualSize   111958 -> 112054   (retail's exactly)
//     .rdata differing      72866 -> 34648
//     .text  differing     397969 -> 397094
//     .reloc differing      31520 -> 29153
//     TOTAL differing (RAW) 538448 -> 496903   (-41545)
//
// Rows are untouched: 4760 / 4933, 2339 aligned, and not one function's ratio
// changed in an address-keyed comparison.
