#ifndef MXRECT32_H
#define MXRECT32_H

#include "mxpoint32.h"
#include "mxsize32.h"

// SIZE 0x10
class MxRect32 {
public:
	MxRect32() {}
	MxRect32(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom) { CopyFrom(p_left, p_top, p_right, p_bottom); }
	MxRect32(const MxPoint32& p_point, const MxSize32& p_size) { CopyFrom(p_point, p_size); }
	MxRect32(const MxRect32& p_a, const MxRect32& p_b)
	{
		m_left = Max(p_a.m_left, p_b.m_left);
		m_top = Max(p_a.m_top, p_b.m_top);
		m_right = Min(p_a.m_right, p_b.m_right);
		m_bottom = Min(p_a.m_bottom, p_b.m_bottom);
	}

	MxRect32(const MxRect32& p_rect) { CopyFrom(p_rect); }

	MxRect32& operator=(const MxRect32& p_rect)
	{
		CopyFrom(p_rect);
		return *this;
	}

	inline void Intersect(const MxRect32& p_rect)
	{
		m_left = Max(p_rect.m_left, m_left);
		m_top = Max(p_rect.m_top, m_top);
		m_right = Min(p_rect.m_right, m_right);
		m_bottom = Min(p_rect.m_bottom, m_bottom);
	}

	inline void SetPoint(const MxPoint32& p_point)
	{
		this->m_left = p_point.GetX();
		this->m_top = p_point.GetY();
	}

	inline void AddPoint(const MxPoint32& p_point)
	{
		this->m_left += p_point.GetX();
		this->m_top += p_point.GetY();
		this->m_right += p_point.GetX();
		this->m_bottom += p_point.GetY();
	}

	inline void SubtractPoint(const MxPoint32& p_point)
	{
		this->m_left -= p_point.GetX();
		this->m_top -= p_point.GetY();
		this->m_right -= p_point.GetX();
		this->m_bottom -= p_point.GetY();
	}

	inline void UpdateBounds(const MxRect32& p_rect)
	{
		m_left = Min(m_left, p_rect.m_left);
		m_top = Min(m_top, p_rect.m_top);
		m_right = Max(m_right, p_rect.m_right);
		m_bottom = Max(m_bottom, p_rect.m_bottom);
	}

	inline MxBool IsValid() const { return m_left < m_right && m_top < m_bottom; }

	inline MxBool IntersectsWith(const MxRect32& p_rect) const
	{
		return m_left < p_rect.m_right && p_rect.m_left < m_right && m_top < p_rect.m_bottom && p_rect.m_top < m_bottom;
	}

	inline MxS32 GetWidth() const { return (m_right - m_left) + 1; }
	inline MxS32 GetHeight() const { return (m_bottom - m_top) + 1; }

	inline MxPoint32 GetPoint() const { return MxPoint32(this->m_left, this->m_top); }
	inline MxSize32 GetSize() const { return MxSize32(this->m_right, this->m_bottom); }

	inline MxS32 GetLeft() const { return m_left; }
	inline MxS32 GetTop() const { return m_top; }
	inline MxS32 GetRight() const { return m_right; }
	inline MxS32 GetBottom() const { return m_bottom; }

	inline void SetLeft(MxS32 p_left) { m_left = p_left; }
	inline void SetTop(MxS32 p_top) { m_top = p_top; }
	inline void SetRight(MxS32 p_right) { m_right = p_right; }
	inline void SetBottom(MxS32 p_bottom) { m_bottom = p_bottom; }

private:
	inline void CopyFrom(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom)
	{
		this->m_left = p_left;
		this->m_top = p_top;
		this->m_right = p_right;
		this->m_bottom = p_bottom;
	}

	inline void CopyFrom(const MxRect32& p_rect)
	{
		this->m_left = p_rect.m_left;
		this->m_top = p_rect.m_top;
		this->m_right = p_rect.m_right;
		this->m_bottom = p_rect.m_bottom;
	}

	// The address might also be the constructor that calls CopyFrom
	// FUNCTION: LEGO1 0x100b6fc0
	inline MxRect32* CopyFrom(const MxPoint32& p_point, const MxSize32& p_size)
	{
		this->m_left = p_point.GetX();
		this->m_top = p_point.GetY();
		this->m_right = p_size.GetWidth() + p_point.GetX() - 1;
		this->m_bottom = p_size.GetHeight() + p_point.GetY() - 1;
		return this;
	}

	inline static MxS32 Min(MxS32 p_a, MxS32 p_b) { return p_a <= p_b ? p_a : p_b; }
	inline static MxS32 Max(MxS32 p_a, MxS32 p_b) { return p_a <= p_b ? p_b : p_a; }

	MxS32 m_left;   // 0x00
	MxS32 m_top;    // 0x04
	MxS32 m_right;  // 0x08
	MxS32 m_bottom; // 0x0c
};

#endif // MXRECT32_H
