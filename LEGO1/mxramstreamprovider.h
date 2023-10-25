#ifndef MXRAMSTREAMPROVIDER_H
#define MXRAMSTREAMPROVIDER_H

#include "mxstreamprovider.h"

// VTABLE 0x100dd0d0
class MxRAMStreamProvider : public MxStreamProvider {
public:
	MxRAMStreamProvider();
	virtual ~MxRAMStreamProvider() override;

	virtual MxResult SetResourceToGet(void* p_resource) override; // vtable+0x14
	virtual MxU32 GetFileSize() override;                         // vtable+0x18
	virtual MxU32 GetStreamBuffersNum() override;                 // vtable+0x1c
	virtual MxU32 GetLengthInDWords() override;                   // vtable+0x24
	virtual MxU32* GetBufferForDWords() override;                 // vtable+0x28

protected:
	MxU32 m_bufferSize;
	MxU32 m_fileSize;
	void* m_pBufferOfFileSize;
	MxU32 m_lengthInDWords;
	MxU32* m_bufferForDWords;
};

#endif // MXRAMSTREAMPROVIDER_H
