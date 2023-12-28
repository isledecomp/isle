#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "decomp.h"
#include "extra.h"
#include "legoroi.h"
#include "mxdsobject.h"
#include "mxentity.h"
#include "realtime/vector.h"

// VTABLE: LEGO1 0x100d4858
// SIZE 0x68 (probably)
class LegoEntity : public MxEntity {
public:
	// Inlined at 0x100853f7
	inline LegoEntity() { Init(); }

	__declspec(dllexport) virtual ~LegoEntity() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x1000c2f0
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0064
		return "LegoEntity";
	}

	// FUNCTION: LEGO1 0x1000c300
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoEntity::ClassName()) || MxEntity::IsA(p_name);
	}

	virtual MxResult Create(MxDSObject& p_dsObject);                                           // vtable+0x18
	virtual void Destroy(MxBool p_fromDestructor);                                             // vtable+0x1c
	virtual void ParseAction(char*);                                                           // vtable+0x20
	virtual void SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2);                       // vtable+0x24
	virtual void SetWorldTransform(Vector3Impl& p_loc, Vector3Impl& p_dir, Vector3Impl& p_up); // vtable+0x28
	virtual void ResetWorldTransform(MxBool p_inVehicle);                                      // vtable+0x2c
	// FUNCTION: LEGO1 0x10001090
	virtual void SetWorldSpeed(MxFloat p_worldSpeed) { m_worldSpeed = p_worldSpeed; } // vtable+0x30
	virtual void VTable0x34();                                                        // vtable+0x34
	virtual void VTable0x38();                                                        // vtable+0x38
	virtual void VTable0x3c();                                                        // vtable+0x3c
	virtual void VTable0x40();                                                        // vtable+0x40
	virtual void VTable0x44();                                                        // vtable+0x44
	virtual void VTable0x48();                                                        // vtable+0x48
	virtual void VTable0x4c();                                                        // vtable+0x4c

	void FUN_10010c30();
	void SetLocation(Vector3Data& p_location, Vector3Data& p_direction, Vector3Data& p_up, MxBool);

protected:
	void Init();
	void SetWorld();

	undefined m_unk0x10;
	undefined m_unk0x11;
	Vector3Data m_worldLocation;  // 0x14
	Vector3Data m_worldDirection; // 0x28
	Vector3Data m_worldUp;        // 0x3c
	MxFloat m_worldSpeed;         // 0x50
	LegoROI* m_roi;               // 0x54
	MxBool m_cameraFlag;          // 0x58
	undefined m_unk0x59;
	// For tokens from the extra string that look like this:
	// "Action:openram;\lego\scripts\Race\CarRaceR;0"
	ExtraActionType m_actionType; // 0x5c
	char* m_actionArgString;      // 0x60
	MxS32 m_actionArgNumber;      // 0x64
};

#endif // LEGOENTITY_H
