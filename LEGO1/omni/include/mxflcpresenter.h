#ifndef MXFLCPRESENTER_H
#define MXFLCPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

#include <flic.h>

// VTABLE: LEGO1 0x100dc2c0
// SIZE 0x68
class MxFlcPresenter : public MxVideoPresenter {
public:
	MxFlcPresenter();
	~MxFlcPresenter() override;

	// FUNCTION: LEGO1 0x1004e200
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxFlcPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x100b33f0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f43c8
		return "MxFlcPresenter";
	}

	void LoadHeader(MxStreamChunk* p_chunk) override; // vtable+0x5c
	void CreateBitmap() override;                     // vtable+0x60
	void LoadFrame(MxStreamChunk* p_chunk) override;  // vtable+0x68
	void RealizePalette() override;                   // vtable+0x70

	// SYNTHETIC: LEGO1 0x100b3400
	// MxFlcPresenter::`scalar deleting destructor'

protected:
	FLIC_HEADER* m_flcHeader; // 0x64
};

#endif // MXFLCPRESENTER_H
