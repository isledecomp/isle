#ifndef MXFLCPRESENTER_H
#define MXFLCPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

// VTABLEADDR 0x100dc2c0
// SIZE 0x68
class MxFlcPresenter : public MxVideoPresenter {
public:
	MxFlcPresenter();
	virtual ~MxFlcPresenter() override;

	// OFFSET: LEGO1 0x100b33f0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x100f43c8
		return "MxFlcPresenter";
	}

	// OFFSET: LEGO1 0x1004e200
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxFlcPresenter::ClassName()) || MxVideoPresenter::IsA(name);
	}

	undefined4* m_unk64;
};

#endif // MXFLCPRESENTER_H
