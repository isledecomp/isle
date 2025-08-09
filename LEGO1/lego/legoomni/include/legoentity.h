#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "decomp.h"
#include "extra.h"
#include "mxentity.h"

class LegoROI;
class MxDSAction;
class Vector3;

// VTABLE: LEGO1 0x100d4858
// VTABLE: BETA10 0x101b9388
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
		c_disabled = 0x01
	};

	LegoEntity() { Init(); }

	// FUNCTION: LEGO1 0x1000c290
	~LegoEntity() override { Destroy(TRUE); }

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1000c2f0
	// FUNCTION: BETA10 0x10012730
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0064
		return "LegoEntity";
	}

	// FUNCTION: LEGO1 0x1000c300
	// FUNCTION: BETA10 0x100125a0
	MxBool IsA(const char* p_name) const override // vtable+0x10
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
	// FUNCTION: BETA10 0x10013260
	virtual void SetWorldSpeed(MxFloat p_worldSpeed) { m_worldSpeed = p_worldSpeed; } // vtable+0x30

	virtual void ClickSound(MxBool p_basedOnMood); // vtable+0x34
	virtual void ClickAnimation();                 // vtable+0x38
	virtual void SwitchVariant();                  // vtable+0x3c
	virtual void SwitchSound();                    // vtable+0x40
	virtual void SwitchMove();                     // vtable+0x44
	virtual void SwitchColor(LegoROI* p_roi);      // vtable+0x48
	virtual void SwitchMood();                     // vtable+0x4c

	void TransformPointOfView();
	void SetType(MxU8 p_type);
	void SetLocation(const Vector3& p_location, const Vector3& p_direction, const Vector3& p_up, MxBool p_updateCamera);
	Mx3DPointFloat GetWorldDirection();
	Mx3DPointFloat GetWorldUp();
	Mx3DPointFloat GetWorldPosition();

	MxBool IsInteraction(MxU8 p_flag) { return m_interaction & p_flag; }
	MxBool GetFlagsIsSet(MxU8 p_flag) { return m_flags & p_flag; }
	MxU8 GetFlags() { return m_flags; }

	// FUNCTION: BETA10 0x10049db0
	MxFloat GetWorldSpeed() { return m_worldSpeed; }

	// FUNCTION: BETA10 0x1000f2f0
	LegoROI* GetROI() { return m_roi; }

	MxU8 GetType() { return m_type; }

	// FUNCTION: BETA10 0x1007ff00
	MxBool GetCameraFlag() { return m_cameraFlag; }

	void SetFlags(MxU8 p_flags) { m_flags = p_flags; }
	void SetFlag(MxU8 p_flag) { m_flags |= p_flag; }
	void ClearFlag(MxU8 p_flag) { m_flags &= ~p_flag; }
	void SetInteractionFlag(MxU8 p_flag) { m_interaction |= p_flag; }
	void ClearInteractionFlag(MxU8 p_flag) { m_interaction &= ~p_flag; }

protected:
	void Init();
	void SetWorld();

	MxU8 m_interaction;              // 0x10
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

	// variable name verified by BETA10 0x1007eddf
	char* m_siFile; // 0x60

	MxS32 m_targetEntityId; // 0x64
};

// SYNTHETIC: LEGO1 0x1000c3b0
// LegoEntity::`scalar deleting destructor'

#endif // LEGOENTITY_H
