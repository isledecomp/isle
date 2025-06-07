#ifndef LEGOPHONEMEPRESENTER_H
#define LEGOPHONEMEPRESENTER_H

#include "decomp.h"
#include "mxflcpresenter.h"
#include "mxstring.h"
#include "mxtypes.h"

class LegoTextureInfo;

// VTABLE: LEGO1 0x100d8040
// SIZE 0x88
class LegoPhonemePresenter : public MxFlcPresenter {
public:
	LegoPhonemePresenter();
	~LegoPhonemePresenter() override; // vtable+0x00

	// FUNCTION: BETA10 0x100c4220
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f064c
		return "LegoPhonemePresenter";
	}

	// FUNCTION: LEGO1 0x1004e310
	// FUNCTION: BETA10 0x100c41f0
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	void StartingTickle() override;                  // vtable+0x1c
	void EndAction() override;                       // vtable+0x40
	void LoadFrame(MxStreamChunk* p_chunk) override; // vtable+0x68
	void PutFrame() override;                        // vtable+0x6c

	// SYNTHETIC: LEGO1 0x1004e320
	// LegoPhonemePresenter::`scalar deleting destructor'

private:
	void Init();

	MxS32 m_rectCount;              // 0x68
	LegoTextureInfo* m_textureInfo; // 0x6c
	MxBool m_reusedPhoneme;         // 0x70
	MxString m_roiName;             // 0x74
	MxBool m_isPartOfAnimMM;        // 0x84
};

// TEMPLATE: LEGO1 0x1004eb20
// MxListEntry<LegoPhoneme *>::MxListEntry<LegoPhoneme *>

#endif // LEGOPHONEMEPRESENTER_H
