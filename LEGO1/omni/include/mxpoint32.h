#ifndef MXPOINT32_H
#define MXPOINT32_H

#include "mfc.h"
#include "mxtypes.h"

class MxPoint32 : public CPoint {
public:
	MxPoint32() {}

	// FUNCTION: LEGO1 0x10012170
	MxPoint32(MxS32 p_x, MxS32 p_y) : CPoint(p_x, p_y) {}

	MxPoint32(const MxPoint32& p_point)
	{
		x = p_point.x;
		y = p_point.y;
	}

	MxS32 GetX() const { return x; }
	MxS32 GetY() const { return y; }

	void SetX(MxS32 p_x) { x = p_x; }
	void SetY(MxS32 p_y) { y = p_y; }
};

#endif // MXPOINT32_H
