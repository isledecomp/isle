#ifndef MXCONTROLPRESENTER_H
#define MXCONTROLPRESENTER_H

#include "decomp.h"
#include "mxcompositepresenter.h"

// VTABLE: LEGO1 0x100d7b88
// SIZE 0x5c
class MxControlPresenter : public MxCompositePresenter {
public:
	MxControlPresenter();
	virtual ~MxControlPresenter() override;

	// FUNCTION: LEGO1 0x10044000
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0514
		return "MxControlPresenter";
	}

	// FUNCTION: LEGO1 0x10044010
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxControlPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override; // vtable+0x18

private:
	undefined2 m_unk0x4c;
	MxS16 m_unk0x4e;
	undefined m_unk0x50;
	undefined2 m_unk0x52;
	undefined2 m_unk0x54;
	undefined4* m_unk0x58;
};

#endif // MXCONTROLPRESENTER_H
