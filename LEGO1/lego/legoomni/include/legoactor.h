#ifndef LEGOACTOR_H
#define LEGOACTOR_H

#include "decomp.h"
#include "legoentity.h"

class LegoCacheSound;

// VTABLE: LEGO1 0x100d6d68
// VTABLE: BETA10 0x101ba970
// SIZE 0x78
class LegoActor : public LegoEntity {
public:
	enum {
		c_none = 0,
		c_pepper,
		c_mama,
		c_papa,
		c_nick,
		c_laura,
		c_brickster
	};

	LegoActor();
	~LegoActor() override;

	// FUNCTION: LEGO1 0x1002d210
	// FUNCTION: BETA10 0x10012760
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0124
		return "LegoActor";
	}

	// FUNCTION: LEGO1 0x1002d220
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoActor::ClassName()) || LegoEntity::IsA(p_name);
	}

	void ParseAction(char* p_extra) override;                             // vtable+0x20
	void SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2) override; // vtable+0x24

	// FUNCTION: LEGO1 0x10002cc0
	virtual MxFloat GetSoundFrequencyFactor() { return m_frequencyFactor; } // vtable+0x50

	// FUNCTION: LEGO1 0x10002cd0
	virtual void SetSoundFrequencyFactor(MxFloat p_frequencyFactor)
	{
		m_frequencyFactor = p_frequencyFactor;
	} // vtable+0x54

	// FUNCTION: LEGO1 0x10002ce0
	virtual void VTable0x58(MxFloat p_unk0x70) { m_unk0x70 = p_unk0x70; } // vtable+0x58

	// FUNCTION: LEGO1 0x10002cf0
	virtual MxFloat VTable0x5c() { return m_unk0x70; } // vtable+0x5c

	// FUNCTION: LEGO1 0x10002d00
	virtual MxU8 GetActorId() { return m_actorId; } // vtable+0x60

	// FUNCTION: LEGO1 0x10002d10
	virtual void SetActorId(MxU8 p_actorId) { m_actorId = p_actorId; } // vtable+0x64

	static const char* GetActorName(MxU8 p_id);

	void Mute(MxBool p_muted);

protected:
	MxFloat m_frequencyFactor; // 0x68
	LegoCacheSound* m_sound;   // 0x6c
	MxFloat m_unk0x70;         // 0x70
	MxU8 m_actorId;            // 0x74
};

// SYNTHETIC: LEGO1 0x1002d300
// LegoActor::`scalar deleting destructor'

#endif // LEGOACTOR_H
