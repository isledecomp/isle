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
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxStreamController::ClassName()) || MxCore::IsA(name);
	}

	virtual MxResult Open(const char* p_filename);                            // vtable+0x14
	virtual MxResult vtable0x18(undefined4 p_unknown, undefined4 p_unknown2); // vtable+0x18
	virtual MxResult vtable0x1C(undefined4 p_unknown, undefined4 p_unknown2); // vtable+0x1c
	virtual MxResult vtable0x20(MxDSAction* p_action);                        // vtable+0x20
	virtual MxResult vtable0x24(undefined4 p_unknown);                        // vtable+0x24
	MxResult FUN_100c1800(MxDSAction* p_action, MxU32 p_val);
	virtual MxResult vtable0x28();                                        // vtable+0x28
	virtual MxResult vtable0x2c(MxDSAction* p_action, MxU32 p_bufferval); // vtable+0x2c
	virtual MxResult vtable0x30(undefined4 p_unknown);                    // vtable+0x30

	MxBool FUN_100c20d0(MxDSObject& p_obj);
	MxResult FUN_100c1a00(MxDSAction* p_action, MxU32 p_bufferval);

	inline MxAtomId& GetAtom() { return atom; };

protected:
	MxCriticalSection m_criticalSection;                // 0x8
	MxAtomId atom;                                      // 0x24
	MxStreamProvider* m_provider;                       // 0x28
	undefined4 m_unk2c;                                 // 0x2c
	MxStreamListMxDSSubscriber m_subscriberList;        // 0x30
	MxStreamListMxDSAction m_unkList0x3c;               // 0x3c
	MxStreamListMxNextActionDataStart m_nextActionList; // 0x48
	MxStreamListMxDSAction m_unkList0x54;               // 0x54
	MxDSAction* m_action0x60;                           // 0x60
};

#endif // MXSTREAMCONTROLLER_H
