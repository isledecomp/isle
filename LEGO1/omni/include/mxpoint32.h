#ifndef MXPOINT32_H
#define MXPOINT32_H

#include "mxtypes.h"

class MxPoint32 {
public:
	MxPoint32() {}

	// FUNCTION: LEGO1 0x10012170
	MxPoint32(MxS32 p_x, MxS32 p_y) { CopyFrom(p_x, p_y); }

	MxPoint32(const MxPoint32& p_point)
	{
		this->m_x = p_point.m_x;
		this->m_y = p_point.m_y;
	}

	inline MxS32 GetX() const { return m_x; }
	inline MxS32 GetY() const { return m_y; }

	inline void SetX(MxS32 p_x) { m_x = p_x; }
	inline void SetY(MxS32 p_y) { m_y = p_y; }

private:
	inline void CopyFrom(MxS32 p_x, MxS32 p_y)
	{
		this->m_x = p_x;
		this->m_y = p_y;
	}

	MxS32 m_x; // 0x00
	MxS32 m_y; // 0x04
};

#endif // MXPOINT32_H
