#ifndef MXSTREAMPROVIDER_H
#define MXSTREAMPROVIDER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxdsfile.h"

class MxStreamController;
class MxDSAction;

// VTABLE: LEGO1 0x100dd100
// SIZE 0x10
class MxStreamProvider : public MxCore {
public:
	inline MxStreamProvider() : m_pLookup(NULL), m_pFile(NULL) {}

	// FUNCTION: LEGO1 0x100d07e0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		return "MxStreamProvider";
	}

	// FUNCTION: LEGO1 0x100d07f0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxStreamProvider::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult SetResourceToGet(MxStreamController* p_resource); // vtable+0x14
	virtual MxU32 GetFileSize() = 0;                                   // vtable+0x18
	virtual MxS32 GetStreamBuffersNum() = 0;                           // vtable+0x1c
	virtual void VTable0x20(MxDSAction* p_action);                     // vtable+0x20
	virtual MxU32 GetLengthInDWords() = 0;                             // vtable+0x24
	virtual MxU32* GetBufferForDWords() = 0;                           // vtable+0x28

protected:
	MxStreamController* m_pLookup; // 0x08
	MxDSFile* m_pFile;             // 0x0c
};

// SYNTHETIC: LEGO1 0x100d0870
// MxStreamProvider::`scalar deleting destructor'

#endif // MXSTREAMPROVIDER_H
