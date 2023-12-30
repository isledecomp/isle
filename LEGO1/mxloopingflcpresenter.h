#ifndef MXLOOPINGFLCPRESENTER_H
#define MXLOOPINGFLCPRESENTER_H

#include "decomp.h"
#include "mxflcpresenter.h"

// VTABLE: LEGO1 0x100dc480
// SIZE 0x6c
class MxLoopingFlcPresenter : public MxFlcPresenter {
public:
	MxLoopingFlcPresenter();
	virtual ~MxLoopingFlcPresenter() override;

	// FUNCTION: LEGO1 0x100b4380
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x10101e20
		return "MxLoopingFlcPresenter";
	}

	virtual void NextFrame() override; // vtable+0x64

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	undefined4 m_unk0x68;
};

#endif // MXLOOPINGFLCPRESENTER_H
