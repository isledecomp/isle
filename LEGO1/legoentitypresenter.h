#ifndef LEGOENTITYPRESENTER_H
#define LEGOENTITYPRESENTER_H

#include "mxcompositepresenter.h"

// VTABLE 0x100d8398
class LegoEntityPresenter : public MxCompositePresenter {
public:
	LegoEntityPresenter();
	virtual ~LegoEntityPresenter() override; // vtable+0x0

	// OFFSET: LEGO1 0x100534b0
	inline const char* ClassName() const override // vtable+0xc
	{
		// 0x100f06b8
		return "LegoEntityPresenter";
	}

	// OFFSET: LEGO1 0x100534c0
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoEntityPresenter::ClassName()) || MxCompositePresenter::IsA(name);
	}

	virtual void Destroy() override;                   // vtable+0x38
	virtual void Init();                               // vtable+0x68
	virtual undefined4 vtable6c(undefined4 p_unknown); // vtable+0x6c

private:
	void Destroy(MxBool p_fromDestructor);

	undefined4 m_unk4c;
};

#endif // LEGOENTITYPRESENTER_H
