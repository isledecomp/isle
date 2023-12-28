#ifndef MXDISKSTREAMPROVIDER_H
#define MXDISKSTREAMPROVIDER_H

#include "compat.h"
#include "decomp.h"
#include "mxcriticalsection.h"
#include "mxdsaction.h"
#include "mxstreamlist.h"
#include "mxstreamprovider.h"
#include "mxthread.h"

class MxDiskStreamProvider;
class MxDSStreamingAction;

// VTABLE: LEGO1 0x100dd130
// SIZE 0x1c
class MxDiskStreamProviderThread : public MxThread {
public:
	inline MxDiskStreamProviderThread() : MxThread() { m_target = NULL; }

	MxResult Run() override;
	MxResult StartWithTarget(MxDiskStreamProvider* p_target);
};

// VTABLE: LEGO1 0x100dd138
// SIZE 0x60
class MxDiskStreamProvider : public MxStreamProvider {
public:
	MxDiskStreamProvider();
	virtual ~MxDiskStreamProvider() override;

	// FUNCTION: LEGO1 0x100d1160
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x1010287c
		return "MxDiskStreamProvider";
	}

	// FUNCTION: LEGO1 0x100d1170
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDiskStreamProvider::ClassName()) || MxStreamProvider::IsA(p_name);
	}

	MxResult WaitForWorkToComplete();
	MxResult FUN_100d1780(MxDSStreamingAction* p_action);
	void PerformWork();
	static MxBool FUN_100d1af0(MxDSStreamingAction* p_action);
	MxResult FUN_100d1b20(MxDSStreamingAction* p_action);

	virtual MxResult SetResourceToGet(MxStreamController* p_resource) override; // vtable+0x14
	virtual MxU32 GetFileSize() override;                                       // vtable+0x18
	virtual MxS32 GetStreamBuffersNum() override;                               // vtable+0x1c
	virtual void VTable0x20(MxDSAction* p_action) override;                     // vtable+0x20
	virtual MxU32 GetLengthInDWords() override;                                 // vtable+0x24
	virtual MxU32* GetBufferForDWords() override;                               // vtable+0x28

private:
	MxDiskStreamProviderThread m_thread; // 0x10
	MxSemaphore m_busySemaphore;         // 0x2c
	MxBool m_remainingWork;              // 0x34
	MxBool m_unk0x35;                    // 0x35
	MxCriticalSection m_criticalSection; // 0x38
	MxStreamListMxDSAction m_list;       // 0x54
};

#endif // MXDISKSTREAMPROVIDER_H
