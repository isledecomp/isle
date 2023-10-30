#ifndef MXSMKPRESENTER_H
#define MXSMKPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

#include <smk.h>

// VTABLE 0x100dc348
// SIZE 0x720
class MxSmkPresenter : public MxVideoPresenter {
public:
	MxSmkPresenter();
	virtual ~MxSmkPresenter() override;

	virtual void Destroy() override;
	virtual void VTable0x5c(undefined4 p_unknown1) override;
	virtual void VTable0x60() override;
	virtual void VTable0x68(undefined4 p_unknown1) override; // vtable+0x68
	virtual void VTable0x70() override;
	virtual MxU32 VTable0x88();

	struct MxSmack {
		Smack m_smack;

		// Unknown for the time being. Not an immediately
		// recognizable part of the SMK standard...

		undefined m_unk0x3f4[784];
		undefined4* m_unk0x6a0;
		undefined4* m_unk0x6a4;
		undefined4* m_unk0x6a8;
		undefined4* m_unk0x6ac;
		undefined4* m_unk0x6b0;
		undefined4* m_unk0x6b4;
	};

	MxSmack m_mxSmack;
	undefined4 m_unk0x71c;

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	// This should most likely be in a separate translation unit
	static void FUN_100c5d40(MxSmack* p_mxSmack);
};

#endif // MXSMKPRESENTER_H
