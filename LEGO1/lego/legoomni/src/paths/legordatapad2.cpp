#include "legopathboundary.h"

// This translation unit contributes nothing but the file-scope constant pool
// that tglvector.h places in .rdata (Tgl::Constant::Pi and its neighbours) --
// no code, no data, no COMDAT. Retail's .rdata carries 96 bytes of per-object
// constant pool that our object set does not emit, which leaves every .rdata
// contribution from the static libraries onward sitting 96 bytes below its
// retail address. Four of these carriers restore the section to retail's exact
// VirtualSize and re-seat that whole tail. See the note in
// legordatapad1.cpp for the measurement.
