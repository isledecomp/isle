#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legocameracontroller.h"
#include "legoentity.h"
#include "legopathcontrollerlist.h"
#include "mxpresenter.h"
#include "mxpresenterlist.h"

class IslePathActor;

// VTABLE: LEGO1 0x100d6280
// SIZE 0xf8
class LegoWorld : public LegoEntity {
public:
	__declspec(dllexport) LegoWorld();
	__declspec(dllexport) virtual ~LegoWorld(); // vtable+0x0

	virtual MxLong Notify(MxParam& p) override; // vtable+0x4
	MxResult Tickle();

	// FUNCTION: LEGO1 0x1001d690
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0058
		return "LegoWorld";
	}

	// FUNCTION: LEGO1 0x1001d6a0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoWorld::ClassName()) || LegoEntity::IsA(name);
	}

	virtual void Stop();                       // vtable+50
	virtual void VTable0x54();                 // vtable+54
	virtual void VTable0x58(MxCore* p_object); // vtable+58
	virtual MxBool VTable0x5c();               // vtable+5c
	// FUNCTION: LEGO1 0x100010a0
	virtual void VTable0x60() {}           // vtable+60
	virtual MxBool VTable0x64();           // vtable+64
	virtual void VTable0x68(MxBool p_add); // vtable+68

	MxResult SetAsCurrentWorld(MxDSObject& p_dsObject);
	void EndAction(MxPresenter* p_presenter);
	void FUN_1001fc80(IslePathActor* actor);
	inline LegoCameraController* GetCamera() { return m_camera; }
	MxBool FUN_100727e0(MxU32 p, Vector3Data& loc, Vector3Data& dir, Vector3Data& up);
	MxBool FUN_10072980(MxU32 p, Vector3Data& loc, Vector3Data& dir, Vector3Data& up);
	void FUN_10073400();
	void FUN_10073430();

protected:
	LegoPathControllerList m_list0x68; // 0x68
	MxPresenterList m_list0x80;        // 0x80
	LegoCameraController* m_camera;    // 0x98
	undefined m_unk9c[0x1c];
	MxPresenterList m_list0xb8; // 0xb8
	undefined m_unkd0[0x26];
	undefined m_unkf6;
	undefined m_unkf7;
};

void FUN_10015820(MxU32 p_unk1, MxU32 p_unk2);
void FUN_100158e0();
void FUN_10015910(MxU32 p_unk1);
void SetIsWorldActive(MxBool p_isWorldActive);

#endif // LEGOWORLD_H
