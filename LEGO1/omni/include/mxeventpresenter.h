#ifndef MXEVENTPRESENTER_H
#define MXEVENTPRESENTER_H

#include "decomp.h"
#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100dca88
// SIZE 0x54
class MxEventPresenter : public MxMediaPresenter {
public:
	MxEventPresenter();
	~MxEventPresenter() override;

	// FUNCTION: LEGO1 0x100c2c30
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101dcc
		return "MxEventPresenter";
	}

	// FUNCTION: LEGO1 0x100c2c40
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxEventPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                   // vtable+0x18
	void StartingTickle() override;                // vtable+0x1c
	MxResult AddToManager() override;              // vtable+0x34
	void Destroy() override;                       // vtable+0x38
	MxResult PutData() override;                   // vtable+0x4c
	virtual void CopyData(MxStreamChunk* p_chunk); // vtable+0x5c

	// SYNTHETIC: LEGO1 0x100c2d20
	// MxEventPresenter::`scalar deleting destructor'

private:
	void Init();

	MxU8* m_data; // 0x50
};

#endif // MXEVENTPRESENTER_H
