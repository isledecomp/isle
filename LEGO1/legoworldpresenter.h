#ifndef LEGOWORLDPRESENTER_H
#define LEGOWORLDPRESENTER_H

#include "legoentitypresenter.h"

// VTABLE: LEGO1 0x100d8ee0
// SIZE 0x54
class LegoWorldPresenter : public LegoEntityPresenter {
public:
	LegoWorldPresenter();
	virtual ~LegoWorldPresenter() override; // vtable+0x0

	__declspec(dllexport) static void configureLegoWorldPresenter(int param_1);

	// FUNCTION: LEGO1 0x10066630
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0608
		return "LegoWorldPresenter";
	}

	// FUNCTION: LEGO1 0x10066640
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoWorldPresenter::ClassName()) || LegoEntityPresenter::IsA(p_name);
	}

private:
	undefined4 m_unk0x50;
};

#endif // LEGOWORLDPRESENTER_H
