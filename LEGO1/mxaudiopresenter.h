#ifndef MXAUDIOPRESENTER_H
#define MXAUDIOPRESENTER_H

#include "decomp.h"
#include "mxmediapresenter.h"

// VTABLE 0x100d4c70
// SIZE 0x54
class MxAudioPresenter : public MxMediaPresenter {
public:
	MxAudioPresenter() { m_volume = 100; }

	// OFFSET: LEGO1 0x1000d280
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f078c
		return "MxAudioPresenter";
	}

	// OFFSET: LEGO1 0x1000d290
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxAudioPresenter::ClassName()) || MxMediaPresenter::IsA(name);
	}

	virtual MxU32 GetVolume();              // vtable+0x5c
	virtual void SetVolume(MxU32 p_volume); // vtable+0x60

private:
	MxU32 m_volume;
};

#endif // MXAUDIOPRESENTER_H
