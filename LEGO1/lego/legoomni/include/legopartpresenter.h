#ifndef LEGOPARTPRESENTER_H
#define LEGOPARTPRESENTER_H

#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100d4df0
// SIZE 0x54 (from inlined construction at 0x10009fac)
class LegoPartPresenter : public MxMediaPresenter {
public:
	LegoPartPresenter() { Reset(); }

	// FUNCTION: LEGO1 0x10067300
	~LegoPartPresenter() override { Destroy(TRUE); }

	// FUNCTION: LEGO1 0x1000cf70
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f05d8
		return "LegoPartPresenter";
	}

	// FUNCTION: LEGO1 0x1000cf80
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoPartPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	void ReadyTickle() override;      // vtable+0x18
	MxResult AddToManager() override; // vtable+0x34
	void Destroy() override;          // vtable+0x38

	static void configureLegoPartPresenter(MxS32, MxS32);

	// SYNTHETIC: LEGO1 0x1000d060
	// LegoPartPresenter::`scalar deleting destructor'

	inline void Reset() { m_partData = NULL; }

	MxResult Read(MxDSChunk& p_chunk);
	void FUN_1007df20();

private:
	void Destroy(MxBool p_fromDestructor);

	MxDSChunk* m_partData; // 0x54
};

#endif // LEGOPARTPRESENTER_H
