#ifndef LEGOMETERPRESENTER_H
#define LEGOMETERPRESENTER_H

#include "mxstillpresenter.h"

// VTABLE: LEGO1 0x100d7ac8
// SIZE 0x94 (from 0x1000a163)
class LegoMeterPresenter : public MxStillPresenter {
public:
	LegoMeterPresenter();
	// FUNCTION: LEGO1 0x10043550
	virtual ~LegoMeterPresenter() override{};
	// MxStillPresenter's `::ClassName` and `::IsA` are used.

	virtual void StreamingTickle() override; // vtable+0x20
	virtual void RepeatingTickle() override; // vtable+0x24
	virtual void ParseExtra() override;      // vtable+0x30

private:
	MxU8* m_unk0x6c;     // 0x6c
	MxU16 m_type;        // 0x70
	MxString m_variable; // 0x74
	MxFloat m_unk0x84;   // 0x84
	MxU16 m_unk0x88;     // 0x88
	MxU16 m_unk0x8a;     // 0x8a
	MxU16 m_unk0x8c;     // 0x8c
	MxU16 m_unk0x8e;     // 0x8e
	MxU16 m_layout;      // 0x90

	void FUN_10043a50();
};

#endif // LEGOMETERPRESENTER_H
