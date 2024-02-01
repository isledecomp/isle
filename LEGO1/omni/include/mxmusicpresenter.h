#ifndef MXMUSICPRESENTER_H
#define MXMUSICPRESENTER_H

#include "mxaudiopresenter.h"

// VTABLE: LEGO1 0x100dc9b8
// SIZE 0x54
class MxMusicPresenter : public MxAudioPresenter {
public:
	MxMusicPresenter();
	~MxMusicPresenter() override;

	// FUNCTION: LEGO1 0x100c23a0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101e48
		return "MxMusicPresenter";
	}

	// FUNCTION: LEGO1 0x100c23b0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxMusicPresenter::ClassName()) || MxAudioPresenter::IsA(p_name);
	}

	MxResult AddToManager() override; // vtable+0x34
	void Destroy() override;          // vtable+0x38

	// SYNTHETIC: LEGO1 0x100c24c0
	// MxMusicPresenter::`scalar deleting destructor'

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);
};

#endif // MXMUSICPRESENTER_H
