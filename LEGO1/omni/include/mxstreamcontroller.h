#ifndef MXSTREAMCONTROLLER_H
#define MXSTREAMCONTROLLER_H

#include "decomp.h"
#include "mxatom.h"
#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxdsobject.h"
#include "mxdssubscriber.h"
#include "mxnextactiondatastart.h"
#include "mxstl/stlcompat.h"

class MxDSAction;
class MxDSStreamingAction;
class MxStreamProvider;

// SIZE 0x0c
class MxNextActionDataStartList : public MxUtilityList<MxNextActionDataStart*> {
public:
	MxNextActionDataStart* Find(MxU32 p_id, MxS16 p_value);
	MxNextActionDataStart* FindAndErase(MxU32 p_id, MxS16 p_value);
};

// VTABLE: LEGO1 0x100dc968
// VTABLE: BETA10 0x101c26c0
// SIZE 0x64
class MxStreamController : public MxCore {
public:
	MxStreamController();
	~MxStreamController() override; // vtable+0x00

	// FUNCTION: LEGO1 0x100c0f10
	// FUNCTION: BETA10 0x10146cf0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10102130
		return "MxStreamController";
	}

	// FUNCTION: LEGO1 0x100c0f20
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStreamController::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult Open(const char* p_filename); // vtable+0x14

	// FUNCTION: LEGO1 0x100b9400
	virtual MxResult VTable0x18(undefined4, undefined4) { return FAILURE; } // vtable+0x18

	// FUNCTION: LEGO1 0x100b9410
	virtual MxResult VTable0x1c(undefined4, undefined4) { return FAILURE; } // vtable+0x1c

	virtual MxResult VTable0x20(MxDSAction* p_action); // vtable+0x20
	virtual MxResult VTable0x24(MxDSAction* p_action); // vtable+0x24

	// FUNCTION: LEGO1 0x100b9420
	virtual MxDSStreamingAction* VTable0x28() { return NULL; } // vtable+0x28

	virtual MxResult VTable0x2c(MxDSAction* p_action, MxU32 p_bufferval); // vtable+0x2c
	virtual MxResult VTable0x30(MxDSAction* p_action);                    // vtable+0x30

	void AddSubscriber(MxDSSubscriber* p_subscriber);
	void RemoveSubscriber(MxDSSubscriber* p_subscriber);
	MxResult FUN_100c1800(MxDSAction* p_action, MxU32 p_val);
	MxResult FUN_100c1a00(MxDSAction* p_action, MxU32 p_offset);
	MxPresenter* FUN_100c1e70(MxDSAction& p_action);
	MxResult FUN_100c1f00(MxDSAction* p_action);
	MxBool IsStoped(MxDSObject* p_obj);
	MxResult InsertActionToList54(MxDSAction* p_action);
	MxNextActionDataStart* FindNextActionDataStartFromStreamingAction(MxDSStreamingAction* p_action);

	MxAtomId& GetAtom() { return m_atom; }
	MxStreamProvider* GetProvider() { return m_provider; }
	MxDSObjectList& GetUnk0x3c() { return m_unk0x3c; }
	MxDSObjectList& GetUnk0x54() { return m_unk0x54; }
	MxDSSubscriberList& GetSubscriberList() { return m_subscriberList; }

protected:
	MxCriticalSection m_criticalSection;        // 0x08
	MxAtomId m_atom;                            // 0x24
	MxStreamProvider* m_provider;               // 0x28
	undefined4* m_unk0x2c;                      // 0x2c
	MxDSSubscriberList m_subscriberList;        // 0x30
	MxDSObjectList m_unk0x3c;                   // 0x3c
	MxNextActionDataStartList m_nextActionList; // 0x48
	MxDSObjectList m_unk0x54;                   // 0x54
	MxDSAction* m_action0x60;                   // 0x60
};

// TEMPLATE: LEGO1 0x100c0d60
// list<MxDSObject *,allocator<MxDSObject *> >::~list<MxDSObject *,allocator<MxDSObject *> >

// TEMPLATE: LEGO1 0x100c0dd0
// list<MxDSSubscriber *,allocator<MxDSSubscriber *> >::~list<MxDSSubscriber *,allocator<MxDSSubscriber *> >

// TEMPLATE: LEGO1 0x100c0e40
// list<MxDSSubscriber *,allocator<MxDSSubscriber *> >::_Buynode

// clang-format off
// TEMPLATE: LEGO1 0x100c0e70
// list<MxNextActionDataStart *,allocator<MxNextActionDataStart *> >::~list<MxNextActionDataStart *,allocator<MxNextActionDataStart *> >
// clang-format on

// TEMPLATE: LEGO1 0x100c0ee0
// list<MxNextActionDataStart *,allocator<MxNextActionDataStart *> >::_Buynode

// SYNTHETIC: LEGO1 0x100c0fa0
// MxStreamController::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100c0fc0
// MxDSSubscriberList::~MxDSSubscriberList

// FUNCTION: LEGO1 0x100c1010
// MxDSObjectList::~MxDSObjectList

// FUNCTION: LEGO1 0x100c1060
// MxNextActionDataStartList::~MxNextActionDataStartList

// TEMPLATE: LEGO1 0x100c10b0
// MxUtilityList<MxDSSubscriber *>::~MxUtilityList<MxDSSubscriber *>

// TEMPLATE: LEGO1 0x100c1100
// MxUtilityList<MxDSObject *>::~MxUtilityList<MxDSObject *>

// TEMPLATE: LEGO1 0x100c1150
// MxUtilityList<MxNextActionDataStart *>::~MxUtilityList<MxNextActionDataStart *>

// TEMPLATE: LEGO1 0x100c11a0
// List<MxDSSubscriber *>::~List<MxDSSubscriber *>

// TEMPLATE: LEGO1 0x100c11f0
// List<MxDSObject *>::~List<MxDSObject *>

// TEMPLATE: LEGO1 0x100c1240
// List<MxNextActionDataStart *>::~List<MxNextActionDataStart *>

// TEMPLATE: LEGO1 0x100c1bc0
// list<MxDSObject *,allocator<MxDSObject *> >::insert

#endif // MXSTREAMCONTROLLER_H
