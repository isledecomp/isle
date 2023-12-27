#ifndef MXRAMSTREAMPROVIDER_H
#define MXRAMSTREAMPROVIDER_H

#include "mxstreamprovider.h"

// VTABLE: LEGO1 0x100dd0d0
class MxRAMStreamProvider : public MxStreamProvider {
public:
	MxRAMStreamProvider();
	virtual ~MxRAMStreamProvider() override;

	// FUNCTION: LEGO1 0x100d0970
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x10102864
		return "MxRAMStreamProvider";
	}

	// FUNCTION: LEGO1 0x100d0980
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxRAMStreamProvider::ClassName()) || MxStreamProvider::IsA(p_name);
	}

	virtual MxResult SetResourceToGet(MxStreamController* p_resource) override; // vtable+0x14
	virtual MxU32 GetFileSize() override;                                       // vtable+0x18
	virtual MxS32 GetStreamBuffersNum() override;                               // vtable+0x1c
	virtual MxU32 GetLengthInDWords() override;                                 // vtable+0x24
	virtual MxU32* GetBufferForDWords() override;                               // vtable+0x28

	inline MxU32* GetBufferOfFileSize() { return m_pBufferOfFileSize; }

protected:
	MxU32 m_bufferSize;
	MxU32 m_fileSize;
	MxU32* m_pBufferOfFileSize;
	MxU32 m_lengthInDWords;
	MxU32* m_bufferForDWords;
};

#endif // MXRAMSTREAMPROVIDER_H
