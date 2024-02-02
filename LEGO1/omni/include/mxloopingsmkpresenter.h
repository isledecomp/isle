#ifndef MXLOOPINGSMKPRESENTER_H
#define MXLOOPINGSMKPRESENTER_H

#include "decomp.h"
#include "mxsmkpresenter.h"

// VTABLE: LEGO1 0x100dc540
// SIZE 0x724
class MxLoopingSmkPresenter : public MxSmkPresenter {
public:
	MxLoopingSmkPresenter();
	~MxLoopingSmkPresenter() override; // vtable+0x00

	// FUNCTION: LEGO1 0x100b4920
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101e08
		return "MxLoopingSmkPresenter";
	}

	void RepeatingTickle() override;  // vtable+0x24
	MxResult AddToManager() override; // vtable+0x34
	void Destroy() override;          // vtable+0x38
	void NextFrame() override;        // vtable+0x64
	void VTable0x88() override;       // vtable+0x88
	virtual void VTable0x8c();        // vtable+0x8c

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	MxLong m_elapsedDuration; // 0x720
};

// SYNTHETIC: LEGO1 0x100b4930
// MxLoopingSmkPresenter::`scalar deleting destructor'

#endif // MXLOOPINGSMKPRESENTER_H
