#ifndef MXTICKLEMANAGER_H
#define MXTICKLEMANAGER_H

#include "mxcore.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class MxTickleClient {
public:
	MxTickleClient(MxCore* p_client, MxTime p_interval);

	inline MxCore* GetClient() const { return m_client; }

	inline MxTime GetTickleInterval() const { return m_interval; }

	inline MxTime GetLastUpdateTime() const { return m_lastUpdateTime; }

	inline MxU16 GetFlags() const { return m_flags; }

	inline void SetTickleInterval(MxTime p_interval) { m_interval = p_interval; }

	inline void SetLastUpdateTime(MxTime p_lastUpdateTime) { m_lastUpdateTime = p_lastUpdateTime; }

	inline void SetFlags(MxU16 p_flags) { m_flags = p_flags; }

private:
	MxCore* m_client;        // 0x0
	MxTime m_interval;       // 0x4
	MxTime m_lastUpdateTime; // 0x8
	MxU16 m_flags;           // 0xc
};

typedef list<MxTickleClient*> MxTickleClientPtrList;

// VTABLE: LEGO1 0x100d86d8
class MxTickleManager : public MxCore {
public:
	inline MxTickleManager() {}
	virtual ~MxTickleManager(); // vtable+0x0 (scalar deleting destructor)

	virtual MxResult Tickle();                                                 // vtable+0x8
	virtual void RegisterClient(MxCore* p_client, MxTime p_interval);          // vtable+0x14
	virtual void UnregisterClient(MxCore* p_client);                           // vtable+0x18
	virtual void SetClientTickleInterval(MxCore* p_client, MxTime p_interval); // vtable+0x1c
	virtual MxTime GetClientTickleInterval(MxCore* p_client);                  // vtable+0x20

private:
	MxTickleClientPtrList m_clients; // 0x8
};

#define TICKLE_MANAGER_NOT_FOUND 0x80000000

#endif // MXTICKLEMANAGER_H
