#ifndef MXLOOPINGSMKPRESENTER_H
#define MXLOOPINGSMKPRESENTER_H

#include "decomp.h"
#include "mxsmkpresenter.h"

// VTABLE: LEGO1 0x100dc540
// SIZE 0x724
class MxLoopingSmkPresenter : public MxSmkPresenter {
public:
	MxLoopingSmkPresenter();
	virtual ~MxLoopingSmkPresenter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x100b4920
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x10101e08
		return "MxLoopingSmkPresenter";
	}

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	undefined4 m_unk0x720;
};

#endif // MXLOOPINGSMKPRESENTER_H
