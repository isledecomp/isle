#ifndef MXRECT32_H
#define MXRECT32_H

#include "mxpoint32.h"
#include "mxsize32.h"

class MxRect32 {
public:
	MxRect32() {}
	MxRect32(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom)
	{
		this->m_left = p_left;
		this->m_top = p_top;
		this->m_right = p_right;
		this->m_bottom = p_bottom;
	}

	MxRect32(const MxPoint32& p_point, const MxSize32& p_size)
	{
		this->m_left = p_point.m_x;
		this->m_top = p_point.m_y;
		this->m_right = p_size.m_width;
		this->m_bottom = p_size.m_height;
	}

	inline void SetPoint(const MxPoint32& p_point)
	{
		this->m_left = p_point.m_x;
		this->m_top = p_point.m_y;
	}

	inline void SetSize(const MxSize32& p_size)
	{
		this->m_right = p_size.m_width;
		this->m_bottom = p_size.m_height;
	}

	inline MxS32 GetWidth() { return (m_right - m_left) + 1; }
	inline MxS32 GetHeight() { return (m_bottom - m_top) + 1; }

	inline MxPoint32 GetPoint() { return MxPoint32(this->m_left, this->m_top); }

	MxS32 m_left;
	MxS32 m_top;
	MxS32 m_right;
	MxS32 m_bottom;
};

#endif // MXRECT32_H
