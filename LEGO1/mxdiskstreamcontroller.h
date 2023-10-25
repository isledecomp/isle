#ifndef MXDISKSTREAMCONTROLLER_H
#define MXDISKSTREAMCONTROLLER_H

#include "mxstreamcontroller.h"
#include "mxtypes.h"

#include <string.h>

// VTABLE 0x100dccb8
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

	// OFFSET: LEGO1 0x100c7360
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x10102144
		return "MxDiskStreamController";
	}

	// OFFSET: LEGO1 0x100c7370
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDiskStreamController::ClassName()) || MxStreamController::IsA(name);
	}
};

#endif // MXDISKSTREAMCONTROLLER_H
