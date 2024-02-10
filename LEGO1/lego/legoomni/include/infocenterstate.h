#ifndef INFOCENTERSTATE_H
#define INFOCENTERSTATE_H

#include "decomp.h"
#include "legostate.h"
#include "mxstillpresenter.h"

// VTABLE: LEGO1 0x100d93a8
// SIZE 0x94
class InfocenterState : public LegoState {
public:
	InfocenterState();
	~InfocenterState() override;

	// FUNCTION: LEGO1 0x10071840
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04dc
		return "InfocenterState";
	}

	// FUNCTION: LEGO1 0x10071850
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfocenterState::ClassName()) || LegoState::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x10071830
	MxBool VTable0x14() override { return FALSE; } // vtable+0x14

	inline MxS16 GetInfocenterBufferSize() { return sizeof(m_buffer) / sizeof(m_buffer[0]); }
	inline MxStillPresenter* GetInfocenterBufferElement(MxS32 p_index) { return m_buffer[p_index]; }
	inline Playlist& GetExitDialogueAct1() { return m_exitDialogueAct1; }
	inline Playlist& GetExitDialogueAct23() { return m_exitDialogueAct23; }
	inline Playlist& GetUnknown0x68() { return m_unk0x68; }
	inline MxU32 GetUnknown0x74() { return m_unk0x74; }
	inline Playlist* GetReturnDialogue() { return m_returnDialogue; }
	inline Playlist* GetLeaveDialogue() { return m_leaveDialogue; }

	inline void SetUnknown0x74(MxU32 p_unk0x74) { m_unk0x74 = p_unk0x74; }

	// SYNTHETIC: LEGO1 0x10071900
	// InfocenterState::`scalar deleting destructor'

private:
	Playlist m_exitDialogueAct1;   // 0x08
	Playlist m_exitDialogueAct23;  // 0x14
	Playlist m_returnDialogue[3];  // 0x20
	Playlist m_leaveDialogue[3];   // 0x44
	Playlist m_unk0x68;            // 0x68
	MxU32 m_unk0x74;               // 0x74
	MxStillPresenter* m_buffer[7]; // 0x78
};

#endif // INFOCENTERSTATE_H
