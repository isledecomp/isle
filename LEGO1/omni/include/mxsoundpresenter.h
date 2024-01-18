#ifndef MXSOUNDPRESENTER_H
#define MXSOUNDPRESENTER_H

#include "mxaudiopresenter.h"
#include "mxomni.h"

// VTABLE: LEGO1 0x100d4b08
// SIZE 0x54
class MxSoundPresenter : public MxAudioPresenter {
public:
	// FUNCTION: LEGO1 0x1000d430
	virtual ~MxSoundPresenter() override { Destroy(TRUE); };

	// FUNCTION: LEGO1 0x1000d4a0
	inline virtual const char* ClassName() const // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07a0
		return "MxSoundPresenter";
	};

	// FUNCTION: LEGO1 0x1000d4b0
	inline virtual MxBool IsA(const char* p_name) const // vtable+0x10
	{
		return !strcmp(p_name, MxSoundPresenter::ClassName()) || MxAudioPresenter::IsA(p_name);
	};

	virtual MxResult AddToManager() override; // vtable+0x34

	// FUNCTION: LEGO1 0x1000d490
	virtual void Destroy() override { Destroy(FALSE); }; // vtable+0x38

	// SYNTHETIC: LEGO1 0x1000d5c0
	// MxSoundPresenter::`scalar deleting destructor'

protected:
	void Destroy(MxBool p_fromDestructor);
};

#endif // MXSOUNDPRESENTER_H
