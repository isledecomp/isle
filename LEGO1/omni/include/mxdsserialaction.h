#ifndef MXDSSERIALACTION_H
#define MXDSSERIALACTION_H

#include "decomp.h"
#include "mxdsmultiaction.h"

// VTABLE: LEGO1 0x100dcf38
// SIZE 0xa8
class MxDSSerialAction : public MxDSMultiAction {
public:
	MxDSSerialAction();
	~MxDSSerialAction() override;

	void CopyFrom(MxDSSerialAction& p_dsSerialAction);
	MxDSSerialAction& operator=(MxDSSerialAction& p_dsSerialAction);

	// FUNCTION: LEGO1 0x100caad0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f75dc
		return "MxDSSerialAction";
	}

	// FUNCTION: LEGO1 0x100caae0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSSerialAction::ClassName()) || MxDSMultiAction::IsA(p_name);
	}

	MxLong GetDuration() override;                // vtable+24;
	void SetDuration(MxLong p_duration) override; // vtable+28;
	MxDSAction* Clone() override;                 // vtable+2c;

	// SYNTHETIC: LEGO1 0x100cabf0
	// MxDSSerialAction::`scalar deleting destructor'

private:
	MxDSActionListCursor* m_cursor;
	undefined4 m_unk0xa0;
	undefined4 m_unk0xa4;
};

#endif // MXDSSERIALACTION_H
