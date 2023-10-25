#ifndef MXSMKPRESENTER_H
#define MXSMKPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

// VTABLE 0x100dc348
// SIZE 0x720
class MxSmkPresenter : public MxVideoPresenter {
public:
	MxSmkPresenter();

	virtual void VTable0x60() override;

	undefined4 m_unk64;
	MxS32 m_smkWidth;  // 0x68
	MxS32 m_smkHeight; // 0x6c
	undefined4 m_unk70[427];
	undefined4 m_unk71c;

private:
	void Init();
};

#endif // MXSMKPRESENTER_H
