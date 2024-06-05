#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "decomp.h"
#include "extra.h"
#include "mxentity.h"

class LegoROI;
class MxDSAction;
class Vector3;

// VTABLE: LEGO1 0x100d4858
// SIZE 0x68
class LegoEntity : public MxEntity {
public:
	enum Type {
		e_actor = 0,
		e_unk1,
		e_plant,
		e_building,
		e_autoROI
	};

	enum {
		c_bit1 = 0x01,
		c_managerOwned = 0x02
	};

	enum {
		c_altBit1 = 0x01
	};

	inline LegoEntity() { Init(); }

	// FUNCTION: LEGO1 0x1000c290
	~LegoEntity() override { Destroy(TRUE); }

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1000c2f0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0064
		return "LegoEntity";
	}

	// FUNCTION: LEGO1 0x1000c300
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoEntity::ClassName()) || MxEntity::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction);                     // vtable+0x18
	virtual void Destroy(MxBool p_fromDestructor);                       // vtable+0x1c
	virtual void ParseAction(char* p_extra);                             // vtable+0x20
	virtual void SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2); // vtable+0x24
	virtual void SetWorldTransform(
		const Vector3& p_location,
		const Vector3& p_direction,
		const Vector3& p_up
	);                                                     // vtable+0x28
	virtual void ResetWorldTransform(MxBool p_cameraFlag); // vtable+0x2c

	// FUNCTION: LEGO1 0x10001090
	virtual void SetWorldSpeed(MxFloat p_worldSpeed) { m_worldSpeed = p_worldSpeed; } // vtable+0x30

	virtual void ClickSound(MxBool p_und);    // vtable+0x34
	virtual void ClickAnimation();            // vtable+0x38
	virtual void SwitchVariant();             // vtable+0x3c
	virtual void SwitchSound();               // vtable+0x40
	virtual void SwitchMove();                // vtable+0x44
	virtual void SwitchColor(LegoROI* p_roi); // vtable+0x48
	virtual void SwitchMood();                // vtable+0x4c

	void FUN_10010c30();
	void SetType(MxU8 p_type);
	void SetLocation(const Vector3& p_location, const Vector3& p_direction, const Vector3& p_up, MxBool p_und);
	Mx3DPointFloat GetWorldDirection();
	Mx3DPointFloat GetWorldUp();
	Mx3DPointFloat GetWorldPosition();

	inline MxBool GetUnknown0x10IsSet(MxU8 p_flag) { return m_unk0x10 & p_flag; }
	inline MxBool GetFlagsIsSet(MxU8 p_flag) { return m_flags & p_flag; }
	inline MxU8 GetFlags() { return m_flags; }
	inline MxFloat GetWorldSpeed() { return m_worldSpeed; }
	inline LegoROI* GetROI() { return m_roi; }
	inline MxU8 GetType() { return m_type; }
	inline MxBool GetCameraFlag() { return m_cameraFlag; }

	inline void SetFlags(MxU8 p_flags) { m_flags = p_flags; }
	inline void SetFlag(MxU8 p_flag) { m_flags |= p_flag; }
	inline void ClearFlag(MxU8 p_flag) { m_flags &= ~p_flag; }
	inline void SetUnknown0x10Flag(MxU8 p_flag) { m_unk0x10 |= p_flag; }
	inline void ClearUnknown0x10Flag(MxU8 p_flag) { m_unk0x10 &= ~p_flag; }

protected:
	void Init();
	void SetWorld();

	MxU8 m_unk0x10;                  // 0x10
	MxU8 m_flags;                    // 0x11
	Mx3DPointFloat m_worldLocation;  // 0x14
	Mx3DPointFloat m_worldDirection; // 0x28
	Mx3DPointFloat m_worldUp;        // 0x3c
	MxFloat m_worldSpeed;            // 0x50
	LegoROI* m_roi;                  // 0x54
	MxBool m_cameraFlag;             // 0x58
	MxU8 m_type;                     // 0x59
	// For tokens from the extra string that look like this:
	// "Action:openram;\lego\scripts\Race\CarRaceR;0"
	Extra::ActionType m_actionType; // 0x5c
	char* m_filename;               // 0x60
	MxS32 m_targetEntityId;         // 0x64
};

// SYNTHETIC: LEGO1 0x1000c3b0
// LegoEntity::`scalar deleting destructor'

#endif // LEGOENTITY_H
