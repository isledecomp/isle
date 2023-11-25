#ifndef MXFLCPRESENTER_H
#define MXFLCPRESENTER_H

#include "decomp.h"

#include <flic.h>

#include "mxvideopresenter.h"

// VTABLE 0x100dc2c0
// SIZE 0x68
class MxFlcPresenter : public MxVideoPresenter {
public:
	MxFlcPresenter();
	virtual ~MxFlcPresenter() override;

	// OFFSET: LEGO1 0x1004e200
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxFlcPresenter::ClassName()) || MxVideoPresenter::IsA(name);
	}

	// OFFSET: LEGO1 0x100b33f0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x100f43c8
		return "MxFlcPresenter";
	}

	virtual void vtable60() override; // vtable+0x60
	virtual void VTable0x70() override; // vtable+0x70

	FLIC_HEADER* m_unk64; // 0x64 - what we believe so far. Could be another custom structure like MxSmack.
};

#endif // MXFLCPRESENTER_H
