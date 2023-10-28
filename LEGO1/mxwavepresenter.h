#ifndef MXWAVEPRESENTER_H
#define MXWAVEPRESENTER_H

#include "decomp.h"
#include "mxsoundpresenter.h"

// VTABLE 0x100d49a8
// SIZE 0x6c
class MxWavePresenter : public MxSoundPresenter {
private:
	void Init();

public:
	MxWavePresenter() { Init(); }

	// OFFSET: LEGO1 0x1000d6c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f07b4
		return "MxWavePresenter";
	}

	// OFFSET: LEGO1 0x1000d6d0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxWavePresenter::ClassName()) || MxSoundPresenter::IsA(name);
	}

	virtual void VTable0x64();      // vtable+0x64
	virtual void VTable0x68();      // vtable+0x68
	virtual undefined VTable0x6c(); // vtable+0x6c

private:
	undefined4 m_unk54;
	undefined4 m_unk58;
	undefined4 m_unk5c;
	undefined4 m_unk60;
	undefined m_unk64;
	undefined m_unk65;
	undefined m_unk66;
	undefined m_unk67;
	undefined m_unk68;
};

#endif // MXWAVEPRESENTER_H
