#ifndef MXRECT32_H
#define MXRECT32_H

#include "mfc.h"
#include "mxpoint32.h"
#include "mxsize32.h"

// TODO: We recently added the MFC base class.
// We have to check all usage sites of MxRect32 and verify with the help of the BETA
// whether MxRect32 or CRect has been used.
// Functions like CopyFrom or the other utility functions may take different types.

// SIZE 0x10
class MxRect32 : public CRect {
public:
	MxRect32() {}
	MxRect32(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom) : CRect(p_left, p_top, p_right, p_bottom) {}
	MxRect32(const MxPoint32& p_point, const MxSize32& p_size) { CopyFrom(p_point, p_size); }
	MxRect32(const MxRect32& p_a, const MxRect32& p_b)
	{
		left = Max(p_a.left, p_b.left);
		top = Max(p_a.top, p_b.top);
		right = Min(p_a.right, p_b.right);
		bottom = Min(p_a.bottom, p_b.bottom);
	}

	MxRect32(const MxRect32& p_rect) { CopyFrom(p_rect); }

	MxRect32& operator=(const MxRect32& p_rect)
	{
		CopyFrom(p_rect);
		return *this;
	}

	void Intersect(const MxRect32& p_rect)
	{
		left = Max(p_rect.left, left);
		top = Max(p_rect.top, top);
		right = Min(p_rect.right, right);
		bottom = Min(p_rect.bottom, bottom);
	}

	void SetPoint(const MxPoint32& p_point)
	{
		left = p_point.GetX();
		top = p_point.GetY();
	}

	void AddPoint(const MxPoint32& p_point)
	{
		left += p_point.GetX();
		top += p_point.GetY();
		right += p_point.GetX();
		bottom += p_point.GetY();
	}

	void SubtractPoint(const MxPoint32& p_point)
	{
		left -= p_point.GetX();
		top -= p_point.GetY();
		right -= p_point.GetX();
		bottom -= p_point.GetY();
	}

	void UpdateBounds(const MxRect32& p_rect)
	{
		left = Min(left, p_rect.left);
		top = Min(top, p_rect.top);
		right = Max(right, p_rect.right);
		bottom = Max(bottom, p_rect.bottom);
	}

	MxBool IsValid() const { return left < right && top < bottom; }

	MxBool IntersectsWith(const MxRect32& p_rect) const
	{
		return left < p_rect.right && p_rect.left < right && top < p_rect.bottom && p_rect.top < bottom;
	}

	MxS32 GetWidth() const { return (right - left) + 1; }
	MxS32 GetHeight() const { return (bottom - top) + 1; }

	MxPoint32 GetPoint() const { return MxPoint32(left, top); }
	MxSize32 GetSize() const { return MxSize32(right, bottom); }

	MxS32 GetLeft() const { return left; }
	MxS32 GetTop() const { return top; }
	MxS32 GetRight() const { return right; }
	MxS32 GetBottom() const { return bottom; }

	void SetLeft(MxS32 p_left) { left = p_left; }
	void SetTop(MxS32 p_top) { top = p_top; }
	void SetRight(MxS32 p_right) { right = p_right; }
	void SetBottom(MxS32 p_bottom) { bottom = p_bottom; }

private:
	void CopyFrom(const MxRect32& p_rect)
	{
		left = p_rect.left;
		top = p_rect.top;
		right = p_rect.right;
		bottom = p_rect.bottom;
	}

	// The address might also be the constructor that calls CopyFrom
	// FUNCTION: LEGO1 0x100b6fc0
	MxRect32* CopyFrom(const MxPoint32& p_point, const MxSize32& p_size)
	{
		left = p_point.GetX();
		top = p_point.GetY();
		right = p_size.GetWidth() + p_point.GetX() - 1;
		bottom = p_size.GetHeight() + p_point.GetY() - 1;
		return this;
	}

	static MxS32 Min(MxS32 p_a, MxS32 p_b) { return p_a <= p_b ? p_a : p_b; }
	static MxS32 Max(MxS32 p_a, MxS32 p_b) { return p_a <= p_b ? p_b : p_a; }
};

#endif // MXRECT32_H
