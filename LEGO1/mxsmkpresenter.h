#ifndef MXSMKPRESENTER_H
#define MXSMKPRESENTER_H

#include "decomp.h"
#include "mxsmack.h"
#include "mxvideopresenter.h"

// VTABLE: LEGO1 0x100dc348
// SIZE 0x720
class MxSmkPresenter : public MxVideoPresenter {
public:
	MxSmkPresenter();
	virtual ~MxSmkPresenter() override;

	// FUNCTION: LEGO1 0x100b3730
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x10101e38
		return "MxSmkPresenter";
	}

	// FUNCTION: LEGO1 0x100b3740
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxSmkPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	virtual MxResult AddToManager() override;                 // vtable+0x34
	virtual void Destroy() override;                          // vtable+0x38
	virtual void LoadHeader(MxStreamChunk* p_chunk) override; // vtable+0x5c
	virtual void CreateBitmap() override;                     // vtable+0x60
	virtual void LoadFrame(MxStreamChunk* p_chunk) override;  // vtable+0x68
	virtual void RealizePalette() override;                   // vtable+0x70
	virtual void VTable0x88();                                // vtable+0x88

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

protected:
	MxSmack m_mxSmack;    // 0x64
	MxU32 m_currentFrame; // 0x71c
};

#endif // MXSMKPRESENTER_H
