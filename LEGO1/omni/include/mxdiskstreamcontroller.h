#ifndef MXDISKSTREAMCONTROLLER_H
#define MXDISKSTREAMCONTROLLER_H

#include "decomp.h"
#include "mxdsbuffer.h"
#include "mxdsstreamingaction.h"
#include "mxstl/stlcompat.h"
#include "mxstreamcontroller.h"
#include "mxtypes.h"

#include <string.h>

// VTABLE: LEGO1 0x100dccb8
// SIZE 0xc8
class MxDiskStreamController : public MxStreamController {
public:
	MxDiskStreamController();
	virtual ~MxDiskStreamController() override;

	virtual MxResult Tickle() override; // vtable+0x8

	// FUNCTION: LEGO1 0x100c7360
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10102144
		return "MxDiskStreamController";
	}

	// FUNCTION: LEGO1 0x100c7370
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDiskStreamController::ClassName()) || MxStreamController::IsA(p_name);
	}

	virtual MxResult Open(const char* p_filename) override;       // vtable+0x14
	virtual MxResult VTable0x18(undefined4, undefined4) override; // vtable+0x18
	virtual MxResult VTable0x20(MxDSAction* p_action) override;   // vtable+0x20
	virtual MxResult VTable0x24(MxDSAction* p_action) override;   // vtable+0x24
	virtual MxDSStreamingAction* VTable0x28() override;           // vtable+0x28
	virtual MxResult VTable0x30(MxDSAction* p_action) override;   // vtable+0x30
	virtual MxResult VTable0x34(undefined4);                      // vtable+0x34

	inline MxBool GetUnk0xc4() const { return m_unk0xc4; }

	MxResult FUN_100c7890(MxDSStreamingAction* p_action);
	void FUN_100c7cb0(MxDSStreamingAction* p_action);
	void FUN_100c7f40(MxDSStreamingAction* p_streamingaction);
	void FUN_100c8120(MxDSAction* p_action);
	void InsertToList74(MxDSBuffer* p_buffer);
	void FUN_100c8670(MxDSStreamingAction* p_streamingAction);

private:
	MxStreamListMxDSAction m_list0x64; // 0x64
	MxBool m_unk0x70;                  // 0x70
	list<MxDSBuffer*> m_list0x74;      // 0x74
	MxStreamListMxDSAction m_list0x80; // 0x80
	undefined2 m_unk0x8c;              // 0x8c
	MxStreamListMxDSAction m_list0x90; // 0x90
	MxCriticalSection m_critical9c;    // 0x9c
	MxStreamListMxDSAction m_list0xb8; // 0xb8
	MxBool m_unk0xc4;                  // 0xc4

	void FUN_100c7970();
	void FUN_100c7ce0(MxDSBuffer* p_buffer);
	MxResult FUN_100c7d10();
	void FUN_100c7980();
	MxDSStreamingAction* FUN_100c7db0();
	MxResult FUN_100c8360(MxDSStreamingAction* p_action);
	void FUN_100c8540();
	void FUN_100c8720();
};

// TEMPLATE: LEGO1 0x100c14d0
// list<MxDSAction *,allocator<MxDSAction *> >::erase

// TEMPLATE: LEGO1 0x100c7330
// list<MxDSAction *,allocator<MxDSAction *> >::_Buynode

// TEMPLATE: LEGO1 0x100c7420
// list<MxDSBuffer *,allocator<MxDSBuffer *> >::~list<MxDSBuffer *,allocator<MxDSBuffer *> >

// TEMPLATE: LEGO1 0x100c7490
// list<MxDSBuffer *,allocator<MxDSBuffer *> >::_Buynode

// SYNTHETIC: LEGO1 0x100c74c0
// MxDiskStreamController::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c74e0
// List<MxDSBuffer *>::~List<MxDSBuffer *>

// TEMPLATE: LEGO1 0x100c7ef0
// list<MxNextActionDataStart *>::insert

#endif // MXDISKSTREAMCONTROLLER_H
