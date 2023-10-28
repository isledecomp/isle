#ifndef MXSTILLPRESENTER_H
#define MXSTILLPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

// VTABLEADDR 0x100d7a38
// SIZE 0x6c
class MxStillPresenter : public MxVideoPresenter {
public:
	virtual void ParseExtra() override; // vtable+0x30

	MxStillPresenter() { m_unk68 = 0; }
	undefined4 m_unk64;
	undefined4 m_unk68;
};

#endif // MXSTILLPRESENTER_H
