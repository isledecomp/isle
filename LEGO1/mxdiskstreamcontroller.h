#ifndef MXDISKSTREAMCONTROLLER_H
#define MXDISKSTREAMCONTROLLER_H

#include "decomp.h"
#include "mxdsbuffer.h"
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

	virtual MxResult Tickle() override;                                                // vtable+0x8
	virtual MxResult Open(const char* p_filename) override;                            // vtable+0x14
	virtual MxResult vtable0x18(undefined4 p_unknown, undefined4 p_unknown2) override; // vtable+0x18
	virtual MxResult vtable0x20(MxDSAction* p_action) override;                        // vtable+0x20
	virtual MxResult vtable0x24(undefined4 p_unknown) override;                        // vtable+0x24
	virtual MxResult vtable0x28() override;                                            // vtable+0x28
	virtual MxResult vtable0x30(undefined4 p_unknown) override;                        // vtable+0x30
	virtual MxResult vtable0x34(undefined4 p_unknown);                                 // vtable+0x34

	// FUNCTION: LEGO1 0x100c7360
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x10102144
		return "MxDiskStreamController";
	}

	// FUNCTION: LEGO1 0x100c7370
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDiskStreamController::ClassName()) || MxStreamController::IsA(p_name);
	}

private:
	MxStreamListMxDSAction m_list0x64; // 0x64
	undefined m_unk0x70;               // 0x70
	list<MxDSBuffer*> m_list0x74;      // 0x74
	MxStreamListMxDSAction m_list0x80; // 0x80
	undefined2 m_unk0x8c;              // 0x8c
	MxStreamListMxDSAction m_list0x90; // 0x90
	MxCriticalSection m_critical9c;    // 0x9c
	MxStreamListMxDSAction m_list0xb8; // 0xb8
	undefined m_unk0xc4;               // 0xc4
};

#endif // MXDISKSTREAMCONTROLLER_H
