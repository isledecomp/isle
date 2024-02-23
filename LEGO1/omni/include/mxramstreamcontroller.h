#ifndef MXRAMSTREAMCONTROLLER_H
#define MXRAMSTREAMCONTROLLER_H

#include "mxdsbuffer.h"
#include "mxdsstreamingaction.h"
#include "mxstreamcontroller.h"

// VTABLE: LEGO1 0x100dc728
// SIZE 0x98
class MxRAMStreamController : public MxStreamController {
public:
	inline MxRAMStreamController() {}

	// FUNCTION: LEGO1 0x100b9430
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10102118
		return "MxRAMStreamController";
	}

	// FUNCTION: LEGO1 0x100b9440
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxRAMStreamController::ClassName()) ||
			   !strcmp(p_name, MxStreamController::ClassName()) || MxCore::IsA(p_name);
	}

	MxResult Open(const char* p_filename) override;
	MxResult VTable0x20(MxDSAction* p_action) override;
	MxResult VTable0x24(MxDSAction* p_action) override;

private:
	MxDSBuffer m_buffer; // 0x64

	MxResult DeserializeObject(MxDSStreamingAction& p_action);
};

// SYNTHETIC: LEGO1 0x100b94f0
// MxRAMStreamController::`scalar deleting destructor'

#endif // MXRAMSTREAMCONTROLLER_H
