#ifndef MXSTILLPRESENTER_H
#define MXSTILLPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

// VTABLE 0x100d7a38
// SIZE 0x6c
class MxStillPresenter : public MxVideoPresenter {
public:
	MxStillPresenter() { m_unk68 = 0; }
	undefined4 m_unk64;
	undefined4 m_unk68;
};

#endif // MXSTILLPRESENTER_H
