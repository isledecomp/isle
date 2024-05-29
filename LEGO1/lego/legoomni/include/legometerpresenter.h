#ifndef LEGOMETERPRESENTER_H
#define LEGOMETERPRESENTER_H

#include "mxstillpresenter.h"
#include "mxstring.h"

struct Rect16 {
	// FUNCTION: BETA10 0x10097ee0
	Rect16(){};

	// FUNCTION: BETA10 0x100981f0
	inline void SetLeft(MxS16 p_value) { m_left = p_value; }

	// FUNCTION: BETA10 0x10098220
	inline void SetTop(MxS16 p_value) { m_top = p_value; }

	// FUNCTION: BETA10 0x10098250
	inline void SetRight(MxS16 p_value) { m_right = p_value; }

	// FUNCTION: BETA10 0x10098280
	inline void SetBottom(MxS16 p_value) { m_bottom = p_value; }

	// FUNCTION: BETA10 0x10098300
	inline MxS16 GetLeft() const { return m_left; }

	// FUNCTION: BETA10 0x10098330
	inline MxS16 GetTop() const { return m_top; }

	// There is no GetRight()

	// FUNCTION: BETA10 0x10098360
	inline MxS16 GetBottom() const { return m_bottom; }

	// FUNCTION: BETA10 0x10098390
	inline MxS16 GetWidth() const { return m_right - m_left + 1; }

	// FUNCTION: BETA10 0x100983c0
	inline MxS16 GetHeight() const { return m_bottom - m_top + 1; }

private:
	MxS16 m_left;
	MxS16 m_top;
	MxS16 m_right;
	MxS16 m_bottom;
};

struct MeterRect : public Rect16 {
	// FUNCTION: BETA10 0x10097eb0
	MeterRect(){};
};

// VTABLE: LEGO1 0x100d7ac8
// VTABLE: BETA10 0x101bca68
// SIZE 0x94
class LegoMeterPresenter : public MxStillPresenter {
public:
	LegoMeterPresenter();
	~LegoMeterPresenter() override;

	// MxStillPresenter's `::ClassName` and `::IsA` are used.

	void StreamingTickle() override; // vtable+0x20
	void RepeatingTickle() override; // vtable+0x24
	void ParseExtra() override;      // vtable+0x30

private:
	enum MeterLayout {
		e_leftToRight = 0,
		e_rightToLeft,
		e_bottomToTop,
		e_topToBottom
	};

	void DrawMeter();

	MxU8* m_meterPixels;   // 0x6c
	MxU16 m_fillColor;     // 0x70
	MxString m_variable;   // 0x74
	MxFloat m_curPercent;  // 0x84
	MeterRect m_meterRect; // 0x88
	MxS16 m_layout;        // 0x90
};

// SYNTHETIC: LEGO1 0x10043760
// LegoMeterPresenter::`scalar deleting destructor'

#endif // LEGOMETERPRESENTER_H
