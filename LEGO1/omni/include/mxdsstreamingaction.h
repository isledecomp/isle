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
	~MxDSStreamingAction() override;

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

	MxBool HasId(MxU32 p_objectId) override; // vtable+34;

	MxResult Init();
	void SetInternalAction(MxDSAction* p_dsAction);
	void FUN_100cd2d0();

	MxU32 GetUnknown94() { return m_unk0x94; }
	MxS32 GetUnknown9c() { return m_unk0x9c; }
	MxDSBuffer* GetUnknowna0() { return m_unk0xa0; }
	MxDSBuffer* GetUnknowna4() { return m_unk0xa4; }
	MxLong GetUnknowna8() { return m_unk0xa8; }
	MxDSAction* GetInternalAction() { return m_internalAction; }
	MxU32 GetBufferOffset() { return m_bufferOffset; }
	void SetUnknown94(MxU32 p_unk0x94) { m_unk0x94 = p_unk0x94; }
	void SetUnknown9c(MxS32 p_unk0x9c) { m_unk0x9c = p_unk0x9c; }
	void SetUnknowna0(MxDSBuffer* p_unk0xa0) { m_unk0xa0 = p_unk0xa0; }
	void SetUnknowna4(MxDSBuffer* p_unk0xa4) { m_unk0xa4 = p_unk0xa4; }
	void SetBufferOffset(MxU32 p_bufferOffset) { m_bufferOffset = p_bufferOffset; }

	// FUNCTION: BETA10 0x10156650
	void ClearUnknowna0() { m_unk0xa0 = NULL; }

	// SYNTHETIC: LEGO1 0x100cd0b0
	// MxDSStreamingAction::`scalar deleting destructor'

private:
	MxU32 m_unk0x94;              // 0x94
	MxU32 m_bufferOffset;         // 0x98
	MxS32 m_unk0x9c;              // 0x9c
	MxDSBuffer* m_unk0xa0;        // 0xa0
	MxDSBuffer* m_unk0xa4;        // 0xa4
	MxLong m_unk0xa8;             // 0xa8
	undefined2 m_unk0xac;         // 0xac
	MxDSAction* m_internalAction; // 0xb0
};

#endif // MXDSSTREAMINGACTION_H
