#ifndef MXSTILLPRESENTER_H
#define MXSTILLPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

// VTABLE 0x100d7a38
// SIZE 0x6c
class MxStillPresenter : public MxVideoPresenter {
public:
    // OFFSET: LEGO1 0x100435c0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x100f0184
		return "MxStillPresenter";
	}

	// OFFSET: LEGO1 0x100435d0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxStillPresenter::ClassName()) || MxVideoPresenter::IsA(name);
	}

	virtual void ParseExtra() override; // vtable+0x30

	MxStillPresenter() { m_unk68 = 0; }
	undefined4 m_unk64;
	undefined4 m_unk68;
};

#endif // MXSTILLPRESENTER_H
