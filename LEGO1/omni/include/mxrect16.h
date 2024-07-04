#ifndef MXRECT16_H
#define MXRECT16_H

#include "mxtypes.h"

// SIZE 0x08
struct MxRect16 {
	// FUNCTION: BETA10 0x10097ee0
	MxRect16() {}

	// FUNCTION: BETA10 0x100981f0
	void SetLeft(MxS16 p_left) { m_left = p_left; }

	// FUNCTION: BETA10 0x10098220
	void SetTop(MxS16 p_top) { m_top = p_top; }

	// FUNCTION: BETA10 0x10098250
	void SetRight(MxS16 p_right) { m_right = p_right; }

	// FUNCTION: BETA10 0x10098280
	void SetBottom(MxS16 p_bottom) { m_bottom = p_bottom; }

	// FUNCTION: BETA10 0x10098300
	MxS16 GetLeft() const { return m_left; }

	// FUNCTION: BETA10 0x10098330
	MxS16 GetTop() const { return m_top; }

	// There is no GetRight()

	// FUNCTION: BETA10 0x10098360
	MxS16 GetBottom() const { return m_bottom; }

	// FUNCTION: BETA10 0x10098390
	MxS16 GetWidth() const { return m_right - m_left + 1; }

	// FUNCTION: BETA10 0x100983c0
	MxS16 GetHeight() const { return m_bottom - m_top + 1; }

private:
	MxS16 m_left;   // 0x00
	MxS16 m_top;    // 0x02
	MxS16 m_right;  // 0x04
	MxS16 m_bottom; // 0x06
};

#endif // MXRECT16_H
