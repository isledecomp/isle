#ifndef MXSIZE32_H
#define MXSIZE32_H

#include "mfc.h"
#include "mxtypes.h"

class MxSize32 : public CSize {
public:
	MxSize32() {}
	MxSize32(MxS32 p_width, MxS32 p_height) : CSize(p_width, p_height) {}

	MxS32 GetWidth() const { return cx; }
	MxS32 GetHeight() const { return cy; }
};

#endif // MXSIZE32_H
