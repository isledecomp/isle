#ifndef MXAUDIOPRESENTER_H
#define MXAUDIOPRESENTER_H

#include "decomp.h"
#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100d4c70
// SIZE 0x54
class MxAudioPresenter : public MxMediaPresenter {
public:
	MxAudioPresenter() { m_volume = 100; }

	// FUNCTION: LEGO1 0x1000d280
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f078c
		return "MxAudioPresenter";
	}

	// FUNCTION: LEGO1 0x1000d290
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxAudioPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	virtual MxS32 GetVolume();              // vtable+0x5c
	virtual void SetVolume(MxS32 p_volume); // vtable+0x60

protected:
	MxS32 m_volume;
};

#endif // MXAUDIOPRESENTER_H
