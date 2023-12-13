#ifndef MXSTREAMCONTROLLER_H
#define MXSTREAMCONTROLLER_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxdsaction.h"
#include "mxdsobject.h"
#include "mxstl/stlcompat.h"
#include "mxstreamlist.h"
#include "mxstreamprovider.h"

// VTABLE: LEGO1 0x100dc968
// SIZE 0x64
class MxStreamController : public MxCore {
public:
	MxStreamController();

	virtual ~MxStreamController() override; // vtable+0x0

	// FUNCTION: LEGO1 0x100c0f10
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x10102130
		return "MxStreamController";
	}

	// FUNCTION: LEGO1 0x100c0f20
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStreamController::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult Open(const char* p_filename);                        // vtable+0x14
	virtual MxResult VTable0x18(undefined4, undefined4);                  // vtable+0x18
	virtual MxResult VTable0x1c(undefined4, undefined4);                  // vtable+0x1c
	virtual MxResult VTable0x20(MxDSAction* p_action);                    // vtable+0x20
	virtual MxResult VTable0x24(MxDSAction* p_action);                    // vtable+0x24
	virtual MxResult VTable0x28();                                        // vtable+0x28
	virtual MxResult VTable0x2c(MxDSAction* p_action, MxU32 p_bufferval); // vtable+0x2c
	virtual MxResult VTable0x30(MxDSAction* p_action);                    // vtable+0x30

	MxResult FUN_100c1800(MxDSAction* p_action, MxU32 p_val);
	MxBool FUN_100c20d0(MxDSObject& p_obj);
	MxResult FUN_100c1a00(MxDSAction* p_action, MxU32 p_bufferval);
	MxResult FUN_100c1f00(MxDSAction* p_action);

	inline MxAtomId& GetAtom() { return m_atom; };
	inline MxStreamListMxDSAction GetUnknown3c() { return m_unk0x3c; };

protected:
	MxCriticalSection m_criticalSection;                // 0x8
	MxAtomId m_atom;                                    // 0x24
	MxStreamProvider* m_provider;                       // 0x28
	undefined4 m_unk0x2c;                               // 0x2c
	MxStreamListMxDSSubscriber m_subscriberList;        // 0x30
	MxStreamListMxDSAction m_unk0x3c;                   // 0x3c
	MxStreamListMxNextActionDataStart m_nextActionList; // 0x48
	MxStreamListMxDSAction m_unk0x54;                   // 0x54
	MxDSAction* m_action0x60;                           // 0x60
};

// TEMPLATE: LEGO1 0x100c0d60
// list<MxDSAction *,allocator<MxDSAction *> >::~list<MxDSAction *,allocator<MxDSAction *> >

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

// FUNCTION: LEGO1 0x100c0fc0
// MxStreamListMxDSSubscriber::~MxStreamListMxDSSubscriber

// FUNCTION: LEGO1 0x100c1010
// MxStreamListMxDSAction::~MxStreamListMxDSAction

// FUNCTION: LEGO1 0x100c1060
// MxStreamListMxNextActionDataStart::~MxStreamListMxNextActionDataStart

// TEMPLATE: LEGO1 0x100c10b0
// MxStreamList<MxDSSubscriber *>::~MxStreamList<MxDSSubscriber *>

// TEMPLATE: LEGO1 0x100c1100
// MxStreamList<MxDSAction *>::~MxStreamList<MxDSAction *>

// TEMPLATE: LEGO1 0x100c1150
// MxStreamList<MxNextActionDataStart *>::~MxStreamList<MxNextActionDataStart *>

// TEMPLATE: LEGO1 0x100c11a0
// List<MxDSSubscriber *>::~List<MxDSSubscriber *>

// TEMPLATE: LEGO1 0x100c11f0
// List<MxDSAction *>::~List<MxDSAction *>

// TEMPLATE: LEGO1 0x100c1240
// List<MxNextActionDataStart *>::~List<MxNextActionDataStart *>

#endif // MXSTREAMCONTROLLER_H
