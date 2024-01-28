#ifndef LEGOPHONEMEPRESENTER_H
#define LEGOPHONEMEPRESENTER_H

#include "decomp.h"
#include "mxflcpresenter.h"
#include "mxstring.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d8040
// SIZE 0x88
class LegoPhonemePresenter : public MxFlcPresenter {
public:
	LegoPhonemePresenter();
	virtual ~LegoPhonemePresenter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x1004e310
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f064c
		return "LegoPhonemePresenter";
	}

	virtual void StartingTickle() override;                  // vtable+0x1c
	virtual void EndAction() override;                       // vtable+0x40
	virtual void LoadFrame(MxStreamChunk* p_chunk) override; // vtable+0x68
	virtual void PutFrame() override;                        // vtable+0x6c

	// SYNTHETIC: LEGO1 0x1004e320
	// LegoPhonemePresenter::`scalar deleting destructor'

private:
	void Init();
	int m_unk0x68;
	int m_unk0x6c;
	undefined m_unk0x70;
	MxString m_string; // 0x74
	undefined m_unk0x84;
};

#endif // LEGOPHONEMEPRESENTER_H
