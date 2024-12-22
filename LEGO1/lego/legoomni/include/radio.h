#ifndef RADIO_H
#define RADIO_H

#include "legostate.h"
#include "mxcore.h"

class LegoControlManagerNotificationParam;
class MxAtomId;
class MxEndActionNotificationParam;

// VTABLE: LEGO1 0x100d6d28
// VTABLE: BETA10 0x101bfb08
// SIZE 0x30
class RadioState : public LegoState {
public:
	RadioState();

	// FUNCTION: LEGO1 0x1002cf60
	// FUNCTION: BETA10 0x100f2850
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04f8
		return "RadioState";
	}

	// FUNCTION: LEGO1 0x1002cf70
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RadioState::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool IsSerializable() override; // vtable+0x14

	// SYNTHETIC: LEGO1 0x1002d020
	// RadioState::`scalar deleting destructor'

	MxBool IsActive() { return m_active; }

	void SetActive(MxBool p_active) { m_active = p_active; }

	undefined4 FUN_1002d090();
	MxBool FUN_1002d0c0(const MxAtomId& p_atom, MxU32 p_objectId);

	// TODO: Most likely getters/setters are not used according to BETA.

	Playlist m_unk0x08[3]; // 0x08
	MxS16 m_unk0x2c;       // 0x2c
	MxBool m_active;       // 0x2e
};

// VTABLE: LEGO1 0x100d6d10
// VTABLE: BETA10 0x101bfaf0
// SIZE 0x10
class Radio : public MxCore {
public:
	Radio();
	~Radio() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1002c8e0
	// FUNCTION: BETA10 0x100f2670
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f328c
		return "Radio";
	}

	// FUNCTION: LEGO1 0x1002c8f0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Radio::ClassName()) || MxCore::IsA(p_name);
	}

	void Initialize(MxBool p_und);
	void CreateState();
	void Play();
	void Stop();

	RadioState* GetState() { return m_state; }

	// SYNTHETIC: LEGO1 0x1002c970
	// Radio::`scalar deleting destructor'

private:
	RadioState* m_state;   // 0x08
	MxBool m_unk0x0c;      // 0x0c
	MxBool m_audioEnabled; // 0x0d

	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param);
};

#endif // RADIO_H
