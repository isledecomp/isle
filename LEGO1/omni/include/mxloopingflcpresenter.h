#ifndef MXLOOPINGFLCPRESENTER_H
#define MXLOOPINGFLCPRESENTER_H

#include "decomp.h"
#include "mxflcpresenter.h"

// VTABLE: LEGO1 0x100dc480
// SIZE 0x6c
class MxLoopingFlcPresenter : public MxFlcPresenter {
public:
	MxLoopingFlcPresenter();
	~MxLoopingFlcPresenter() override;

	// FUNCTION: LEGO1 0x100b4380
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101e20
		return "MxLoopingFlcPresenter";
	}

	void RepeatingTickle() override;  // vtable+0x24
	MxResult AddToManager() override; // vtable+0x34
	void Destroy() override;          // vtable+0x38
	void NextFrame() override;        // vtable+0x64
	virtual void VTable0x88();        // vtable+0x88

	// SYNTHETIC: LEGO1 0x100b4390
	// MxLoopingFlcPresenter::`scalar deleting destructor'

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	MxLong m_elapsedDuration; // 0x68
};

#endif // MXLOOPINGFLCPRESENTER_H
