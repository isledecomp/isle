#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legocameracontroller.h"
#include "legoentity.h"

// VTABLE 0x100d6280
// SIZE 0xf8
class LegoWorld : public LegoEntity {
public:
	__declspec(dllexport) LegoWorld();
	__declspec(dllexport) virtual ~LegoWorld(); // vtable+0x0

	// OFFSET: LEGO1 0x1001d690
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0058
		return "LegoWorld";
	}

	// OFFSET: LEGO1 0x1001d6a0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoWorld::ClassName()) || LegoEntity::IsA(name);
	}

	virtual void Stop();                       // vtable+50
	virtual void VTable0x54();                 // vtable+54
	virtual void VTable0x58(MxCore* p_object); // vtable+58
	virtual MxBool VTable0x5c();               // vtable+5c
	virtual void VTable0x60();                 // vtable+60
	virtual MxBool VTable0x64();               // vtable+64
	virtual void VTable0x68(MxBool p_add);     // vtable+68

	MxResult SetAsCurrentWorld(MxDSObject& p_dsObject);

protected:
	undefined m_unk68[0x30];
	LegoCameraController* m_camera;
	undefined m_unk9c[0x5a];
	undefined m_unkf6;
	undefined m_unkf7;
};

void FUN_10015820(MxU32 p_unk1, MxU32 p_unk2);
void FUN_10015910(MxU32 p_unk1);
void SetIsWorldActive(MxBool p_isWorldActive);

#endif // LEGOWORLD_H
