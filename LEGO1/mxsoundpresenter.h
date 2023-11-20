#ifndef MXSOUNDPRESENTER_H
#define MXSOUNDPRESENTER_H

#include "mxaudiopresenter.h"
#include "mxomni.h"

// VTABLE 0x100d4b08
// SIZE 0x54
class MxSoundPresenter : public MxAudioPresenter {
public:
	virtual ~MxSoundPresenter() override;

	// OFFSET: LEGO1 0x1000d4a0
	inline virtual const char* ClassName() const // vtable+0x0c
	{
		// 0x100f07a0
		return "MxSoundPresenter";
	};

	// OFFSET: LEGO1 0x1000d4b0
	inline virtual MxBool IsA(const char* name) const // vtable+0x10
	{
		return !strcmp(name, MxSoundPresenter::ClassName()) || MxAudioPresenter::IsA(name);
	};

	virtual MxResult AddToManager() override; // vtable+0x34
	virtual void Destroy() override;          // vtable+0x38

protected:
	void Destroy(MxBool p_fromDestructor);
};

#endif // MXSOUNDPRESENTER_H
