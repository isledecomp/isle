#ifndef MXSIZE32_H
#define MXSIZE32_H

#include "mfc.h"
#include "mxtypes.h"

// TODO: We recently added the MFC base class.
// We have to check all usage sites of MxSize32 and verify with the help of the BETA
// whether MxSize32 or CRect has been used.

class MxSize32 : public CSize {
public:
	MxSize32() {}
	MxSize32(MxS32 p_width, MxS32 p_height) : CSize(p_width, p_height) {}

	MxS32 GetWidth() const { return cx; }
	MxS32 GetHeight() const { return cy; }
};

#endif // MXSIZE32_H
