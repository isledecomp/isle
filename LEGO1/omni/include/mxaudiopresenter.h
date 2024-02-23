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
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f078c
		return "MxAudioPresenter";
	}

	// FUNCTION: LEGO1 0x1000d290
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxAudioPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000d260
	virtual MxS32 GetVolume() { return m_volume; } // vtable+0x5c

	// FUNCTION: LEGO1 0x1000d270
	virtual void SetVolume(MxS32 p_volume) { m_volume = p_volume; } // vtable+0x60

protected:
	MxS32 m_volume;
};

// SYNTHETIC: LEGO1 0x1000d370
// MxAudioPresenter::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1000d3e0
// MxAudioPresenter::~MxAudioPresenter

#endif // MXAUDIOPRESENTER_H
