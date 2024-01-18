#ifndef MXEVENTPRESENTER_H
#define MXEVENTPRESENTER_H

#include "decomp.h"
#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100dca88
// SIZE 0x54
class MxEventPresenter : public MxMediaPresenter {
public:
	MxEventPresenter();
	virtual ~MxEventPresenter() override;

	// FUNCTION: LEGO1 0x100c2c30
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x10101dcc
		return "MxEventPresenter";
	}

	// FUNCTION: LEGO1 0x100c2c40
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxEventPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;           // vtable+0x18
	virtual void StartingTickle() override;        // vtable+0x1c
	virtual MxResult AddToManager() override;      // vtable+0x34
	virtual void Destroy() override;               // vtable+0x38
	virtual MxResult PutData() override;           // vtable+0x4c
	virtual void CopyData(MxStreamChunk* p_chunk); // vtable+0x5c

	// SYNTHETIC: LEGO1 0x100c2d20
	// MxEventPresenter::`scalar deleting destructor'

private:
	void Init();

	MxU8* m_data; // 0x50
};

#endif // MXEVENTPRESENTER_H
