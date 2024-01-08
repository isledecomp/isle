#ifndef MXSTILLPRESENTER_H
#define MXSTILLPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

// VTABLE: LEGO1 0x100d7a38
// SIZE 0x6c
class MxStillPresenter : public MxVideoPresenter {
public:
	MxStillPresenter() { m_bitmapInfo = NULL; }
	// FUNCTION: LEGO1 0x10043550
	virtual ~MxStillPresenter() override { Destroy(TRUE); }; // vtable+0x00

	// FUNCTION: LEGO1 0x100435c0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0184
		return "MxStillPresenter";
	}

	// FUNCTION: LEGO1 0x100435d0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStillPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
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
	virtual void RealizePalette() override;                   // vtable+0x70
	virtual void VTable0x88(MxS32 p_x, MxS32 p_y);            // vtable+0x88
	virtual MxStillPresenter* Clone();                        // vtable+0x8c

private:
	void Destroy(MxBool p_fromDestructor);

	MxLong m_chunkTime;         // 0x64
	MxBITMAPINFO* m_bitmapInfo; // 0x68
};

// SYNTHETIC: LEGO1 0x100436e0
// MxStillPresenter::`scalar deleting destructor'

#endif // MXSTILLPRESENTER_H
