#ifndef LEGOMETERPRESENTER_H
#define LEGOMETERPRESENTER_H

#include "mxgeometry.h"
#include "mxstillpresenter.h"
#include "mxstring.h"

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

	MxU8* m_meterPixels;  // 0x6c
	MxU16 m_fillColor;    // 0x70
	MxString m_variable;  // 0x74
	MxFloat m_curPercent; // 0x84
	MxRect16 m_meterRect; // 0x88
	MxS16 m_layout;       // 0x90
};

// SYNTHETIC: LEGO1 0x10043760
// LegoMeterPresenter::`scalar deleting destructor'

#endif // LEGOMETERPRESENTER_H
