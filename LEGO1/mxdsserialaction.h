#ifndef MXDSSERIALACTION_H
#define MXDSSERIALACTION_H

#include "decomp.h"
#include "mxdsmultiaction.h"

// VTABLE: LEGO1 0x100dcf38
// SIZE 0xa8
class MxDSSerialAction : public MxDSMultiAction {
public:
	MxDSSerialAction();
	virtual ~MxDSSerialAction() override;

	void CopyFrom(MxDSSerialAction& p_dsSerialAction);
	MxDSSerialAction& operator=(MxDSSerialAction& p_dsSerialAction);

	// FUNCTION: LEGO1 0x100caad0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f75dc
		return "MxDSSerialAction";
	}

	// FUNCTION: LEGO1 0x100caae0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSSerialAction::ClassName()) || MxDSMultiAction::IsA(name);
	}

	virtual MxLong GetDuration() override;                // vtable+24;
	virtual void SetDuration(MxLong p_duration) override; // vtable+28;
	virtual MxDSAction* Clone() override;                 // vtable+2c;

private:
	MxDSActionListCursor* m_cursor;
	undefined4 m_unk0xa0;
	undefined4 m_unk0xa4;
};

#endif // MXDSSERIALACTION_H
