#ifndef MXSTILLPRESENTER_H
#define MXSTILLPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

// VTABLE: LEGO1 0x100d7a38
// SIZE 0x6c
class MxStillPresenter : public MxVideoPresenter {
public:
	MxStillPresenter() { m_bitmapInfo = NULL; }
	virtual ~MxStillPresenter() override { Destroy(TRUE); }; // vtable+0x00

	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x100f0184
		return "MxStillPresenter";
	}

	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxStillPresenter::ClassName()) || MxVideoPresenter::IsA(name);
	}

	virtual void StartingTickle() override;                   // vtable+0x1c
	virtual void StreamingTickle() override;                  // vtable+0x20
	virtual void RepeatingTickle() override;                  // vtable+0x24
	virtual void ParseExtra() override;                       // vtable+0x30
	virtual void Destroy() override;                          // vtable+0x38
	virtual void Enable(MxBool p_enable) override;            // vtable+0x54
	virtual void LoadHeader(MxStreamChunk* p_chunk) override; // vtable+0x5c
	virtual void CreateBitmap() override;                     // vtable+0x60
	virtual void NextFrame() override;                        // vtable+0x64
	virtual void LoadFrame(MxStreamChunk* p_chunk) override;  // vtable+0x68
	virtual void VTable0x70() override;                       // vtable+0x70
	virtual void VTable0x88(undefined4, undefined4);          // vtable+0x88
	virtual MxStillPresenter* Clone();                        // vtable+0x8c

private:
	void Destroy(MxBool p_fromDestructor);

	undefined4 m_unk64;         // 0x64
	MxBITMAPINFO* m_bitmapInfo; // 0x68
};

#endif // MXSTILLPRESENTER_H
