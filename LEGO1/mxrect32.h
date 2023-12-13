#ifndef MXRECT32_H
#define MXRECT32_H

#include "mxpoint32.h"
#include "mxsize32.h"

// SIZE 0x10
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

	MxRect32(const MxRect32& p_a, const MxRect32& p_b)
	{
		m_left = Max(p_a.m_left, p_b.m_left);
		m_top = Max(p_a.m_top, p_b.m_top);
		m_right = Min(p_a.m_right, p_b.m_right);
		m_bottom = Min(p_a.m_bottom, p_b.m_bottom);
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

	inline MxBool IsValid() { return m_left < m_right && m_top < m_bottom; }
	inline MxBool IntersectsWith(const MxRect32& p_rect)
	{
		return m_left < p_rect.m_right && p_rect.m_left < m_right && m_top < p_rect.m_bottom && p_rect.m_top < m_bottom;
	}

	inline void UpdateBounds(const MxRect32& p_rect)
	{
		m_left = Min(m_left, p_rect.m_left);
		m_top = Min(m_top, p_rect.m_top);
		m_right = Max(m_right, p_rect.m_right);
		m_bottom = Max(m_bottom, p_rect.m_bottom);
	}

	inline MxS32 GetWidth() { return (m_right - m_left) + 1; }
	inline MxS32 GetHeight() { return (m_bottom - m_top) + 1; }

	inline MxPoint32 GetPoint() { return MxPoint32(this->m_left, this->m_top); }
	inline MxSize32 GetSize() { return MxSize32(this->m_right, this->m_bottom); }

	inline MxS32 GetLeft() { return m_left; }
	inline MxS32 GetTop() { return m_top; }
	inline MxS32 GetRight() { return m_right; }
	inline MxS32 GetBottom() { return m_bottom; }

	inline void SetLeft(MxS32 p_left) { m_left = p_left; }
	inline void SetTop(MxS32 p_top) { m_top = p_top; }
	inline void SetRight(MxS32 p_right) { m_right = p_right; }
	inline void SetBottom(MxS32 p_bottom) { m_bottom = p_bottom; }

private:
	inline static MxS32 Min(MxS32 p_a, MxS32 p_b) { return p_a <= p_b ? p_a : p_b; };
	inline static MxS32 Max(MxS32 p_a, MxS32 p_b) { return p_a <= p_b ? p_b : p_a; };

	MxS32 m_left;
	MxS32 m_top;
	MxS32 m_right;
	MxS32 m_bottom;
};

#endif // MXRECT32_H
