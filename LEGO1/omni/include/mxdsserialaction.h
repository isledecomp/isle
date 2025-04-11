#ifndef MXDSSERIALACTION_H
#define MXDSSERIALACTION_H

#include "decomp.h"
#include "mxdsmultiaction.h"

// VTABLE: LEGO1 0x100dcf38
// VTABLE: BETA10 0x101c2940
// SIZE 0xa8
class MxDSSerialAction : public MxDSMultiAction {
public:
	MxDSSerialAction();
	MxDSSerialAction(MxDSSerialAction& p_dsSerialAction);
	~MxDSSerialAction() override;

	void CopyFrom(MxDSSerialAction& p_dsSerialAction);
	MxDSSerialAction& operator=(MxDSSerialAction& p_dsSerialAction);

	// FUNCTION: LEGO1 0x100caad0
	// FUNCTION: BETA10 0x1015b2b0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f75dc
		return "MxDSSerialAction";
	}

	// FUNCTION: LEGO1 0x100caae0
	// FUNCTION: BETA10 0x1015b2d0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSSerialAction::ClassName()) || MxDSMultiAction::IsA(p_name);
	}

	MxLong GetDuration() override;                // vtable+0x24
	void SetDuration(MxLong p_duration) override; // vtable+0x28
	MxDSAction* Clone() override;                 // vtable+0x2c

	// SYNTHETIC: LEGO1 0x100cabf0
	// SYNTHETIC: BETA10 0x1015b330
	// MxDSSerialAction::`scalar deleting destructor'

private:
	MxDSActionListCursor* m_cursor; // 0x9c
	undefined4 m_unk0xa0;           // 0xa0
	undefined4 m_unk0xa4;           // 0xa4
};

#endif // MXDSSERIALACTION_H
