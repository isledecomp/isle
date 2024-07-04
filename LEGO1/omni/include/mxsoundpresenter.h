#ifndef MXSOUNDPRESENTER_H
#define MXSOUNDPRESENTER_H

#include "mxaudiopresenter.h"

// VTABLE: LEGO1 0x100d4b08
// SIZE 0x54
class MxSoundPresenter : public MxAudioPresenter {
public:
	// FUNCTION: LEGO1 0x1000d430
	~MxSoundPresenter() override { Destroy(TRUE); }

	// FUNCTION: BETA10 0x1008ca70
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f07a0
		return "MxSoundPresenter";
	}

	// FUNCTION: LEGO1 0x1000d4a0
	// FUNCTION: BETA10 0x1008ca40
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x1000d4b0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxSoundPresenter::ClassName()) || MxAudioPresenter::IsA(p_name);
	}

	MxResult AddToManager() override; // vtable+0x34

	// FUNCTION: LEGO1 0x1000d490
	void Destroy() override { Destroy(FALSE); } // vtable+0x38

	// SYNTHETIC: LEGO1 0x1000d5c0
	// MxSoundPresenter::`scalar deleting destructor'

protected:
	void Destroy(MxBool p_fromDestructor);
};

#endif // MXSOUNDPRESENTER_H
