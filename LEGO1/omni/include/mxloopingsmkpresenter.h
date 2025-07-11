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

	// FUNCTION: BETA10 0x1012f070
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x10101e08
		return "MxLoopingSmkPresenter";
	}

	// FUNCTION: LEGO1 0x100b4920
	// FUNCTION: BETA10 0x1013c360
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	void RepeatingTickle() override;        // vtable+0x24
	MxResult AddToManager() override;       // vtable+0x34
	void Destroy() override;                // vtable+0x38
	void NextFrame() override;              // vtable+0x64
	void ResetCurrentFrameAtEnd() override; // vtable+0x88
	virtual void LoadFrameIfRequired();     // vtable+0x8c

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	MxLong m_elapsedDuration; // 0x720
};

// SYNTHETIC: LEGO1 0x100b4930
// MxLoopingSmkPresenter::`scalar deleting destructor'

#endif // MXLOOPINGSMKPRESENTER_H
