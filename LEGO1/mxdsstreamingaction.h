#ifndef MXDSSTREAMINGACTION_H
#define MXDSSTREAMINGACTION_H

#include "mxdsaction.h"

class MxDSBuffer;

// VTABLE: LEGO1 0x100dd088
// SIZE 0xb4
class MxDSStreamingAction : public MxDSAction {
public:
	MxDSStreamingAction(MxDSAction& p_dsAction, MxU32 p_offset);
	MxDSStreamingAction(MxDSStreamingAction& p_dsStreamingAction);
	virtual ~MxDSStreamingAction();

	MxDSStreamingAction* CopyFrom(MxDSStreamingAction& p_dsStreamingAction);
	MxDSStreamingAction& operator=(MxDSAction& p_dsAction)
	{
		MxDSAction::operator=(p_dsAction);
		return *this;
	}
	MxDSStreamingAction& operator=(MxDSStreamingAction& p_dsStreamingAction)
	{
		MxDSAction::operator=(p_dsStreamingAction);
		return *this;
	}

	virtual MxBool HasId(MxU32 p_objectId) override; // vtable+34;

	MxResult Init();
	void SetInternalAction(MxDSAction* p_dsAction);
	void FUN_100cd2d0();

	inline MxU32 GetUnknown94() { return m_unk0x94; }
	inline MxDSBuffer* GetUnknowna0() { return m_unk0xa0; }
	inline MxDSBuffer* GetUnknowna4() { return m_unk0xa4; }
	inline void SetUnknowna0(MxDSBuffer* p_unk0xa0) { m_unk0xa0 = p_unk0xa0; }

private:
	MxU32 m_unk0x94;
	MxU32 m_bufferOffset;
	MxS32 m_unk0x9c;
	MxDSBuffer* m_unk0xa0;
	MxDSBuffer* m_unk0xa4;
	MxLong m_unk0xa8;
	undefined2 m_unk0xac;
	MxDSAction* m_internalAction;
};

#endif // MXDSSTREAMINGACTION_H
