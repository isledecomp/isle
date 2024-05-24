#ifndef TOWTRACK_H
#define TOWTRACK_H

#include "decomp.h"
#include "islepathactor.h"

class TowTrackMissionState;

// VTABLE: LEGO1 0x100d7ee0
// SIZE 0x180
class TowTrack : public IslePathActor {
public:
	TowTrack();

	// FUNCTION: LEGO1 0x1004c7c0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03b8
		return "TowTrack";
	}

	// FUNCTION: LEGO1 0x1004c7d0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, TowTrack::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxLong Notify(MxParam& p_param) override;                         // vtable+0x04
	MxResult Create(MxDSAction& p_dsAction) override;                 // vtable+0x18
	void VTable0x70(float p_float) override;                          // vtable+0x70
	MxU32 VTable0xcc() override;                                      // vtable+0xcc
	MxU32 VTable0xd4(LegoControlManagerEvent& p_param) override;      // vtable+0xd4
	MxU32 VTable0xd8(LegoEndAnimNotificationParam& p_param) override; // vtable+0xd8
	MxU32 VTable0xdc(MxType19NotificationParam& p_param) override;    // vtable+0xdc
	void VTable0xe4() override;                                       // vtable+0xe4

	void CreateState();
	void FUN_1004dab0();
	void FUN_1004dad0();

	// SYNTHETIC: LEGO1 0x1004c950
	// TowTrack::`scalar deleting destructor'

private:
	undefined4 m_unk0x160;         // 0x160
	TowTrackMissionState* m_state; // 0x164
	MxS16 m_unk0x168;              // 0x168
	MxS16 m_unk0x16a;              // 0x16a
	MxS16 m_unk0x16c;              // 0x16c
	MxS16 m_unk0x16e;              // 0x16e
	MxS32 m_unk0x170;              // 0x170
	MxS32 m_unk0x174;              // 0x174
	MxFloat m_unk0x178;            // 0x178
	MxFloat m_time;                // 0x17c
};

#endif // TOWTRACK_H
