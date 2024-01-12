#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legocameracontroller.h"
#include "legoentity.h"
#include "legopathcontrollerlist.h"
#include "mxpresenter.h"
#include "mxpresenterlist.h"

class IslePathActor;
class LegoPathBoundary;

// VTABLE: LEGO1 0x100d6280
// SIZE 0xf8
class LegoWorld : public LegoEntity {
public:
	__declspec(dllexport) LegoWorld();
	__declspec(dllexport) virtual ~LegoWorld(); // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x8

	// FUNCTION: LEGO1 0x1001d690
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0058
		return "LegoWorld";
	}

	// FUNCTION: LEGO1 0x1001d6a0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoWorld::ClassName()) || LegoEntity::IsA(p_name);
	}

	virtual void VTable0x50();                 // vtable+50
	virtual void VTable0x54();                 // vtable+54
	virtual void VTable0x58(MxCore* p_object); // vtable+58
	virtual MxBool VTable0x5c();               // vtable+5c
	// FUNCTION: LEGO1 0x100010a0
	virtual void VTable0x60() {}           // vtable+60
	virtual MxBool VTable0x64();           // vtable+64
	virtual void VTable0x68(MxBool p_add); // vtable+68

	inline LegoCameraController* GetCamera() { return m_camera; }
	inline undefined4 GetUnknown0xec() { return m_unk0xec; }

	undefined FUN_100220e0();
	MxResult SetAsCurrentWorld(MxDSObject& p_dsObject);
	void EndAction(MxCore* p_object);
	void FUN_1001fc80(IslePathActor* p_actor);
	MxBool FUN_100727e0(MxU32, Vector3Data& p_loc, Vector3Data& p_dir, Vector3Data& p_up);
	MxBool FUN_10072980(MxU32, Vector3Data& p_loc, Vector3Data& p_dir, Vector3Data& p_up);
	void FUN_10073400();
	void FUN_10073430();
	MxS32 GetCurrPathInfo(LegoPathBoundary** p_path, MxS32& p_value);

protected:
	LegoPathControllerList m_list0x68; // 0x68
	MxPresenterList m_list0x80;        // 0x80
	LegoCameraController* m_camera;    // 0x98
	undefined m_unk0x9c[0x1c];         // 0x9c
	MxPresenterList m_list0xb8;        // 0xb8
	undefined m_unk0xd0[0x1c];         // 0xd0
	undefined4 m_unk0xec;              // 0xec
	undefined4 m_unk0xf0;              // 0xf0
	MxS16 m_unk0xf4;                   // 0xf4
	MxBool m_worldStarted;             // 0xf6
	undefined m_unk0xf7;               // 0xf7
};

// SYNTHETIC: LEGO1 0x1001eed0
// MxPresenterListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001ef40
// MxPtrListCursor<MxPresenter>::~MxPtrListCursor<MxPresenter>

// SYNTHETIC: LEGO1 0x1001ef90
// MxListCursor<MxPresenter *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f000
// MxPtrListCursor<MxPresenter>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001f070
// MxListCursor<MxPresenter *>::~MxListCursor<MxPresenter *>

// FUNCTION: LEGO1 0x1001f0c0
// MxPresenterListCursor::~MxPresenterListCursor

// TEMPLATE: LEGO1 0x10020760
// MxListCursor<MxPresenter *>::MxListCursor<MxPresenter *>

#endif // LEGOWORLD_H
