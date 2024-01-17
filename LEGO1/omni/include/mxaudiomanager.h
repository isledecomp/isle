#ifndef MXAUDIOMANAGER_H
#define MXAUDIOMANAGER_H

#include "decomp.h"
#include "mxmediamanager.h"

// VTABLE: LEGO1 0x100dc6e0
// SIZE 0x30
class MxAudioManager : public MxMediaManager {
public:
	MxAudioManager();
	virtual ~MxAudioManager() override;

	virtual MxResult InitPresenters() override; // vtable+14
	virtual void Destroy() override;            // vtable+18

	// FUNCTION: LEGO1 0x10029910
	virtual MxS32 GetVolume() { return this->m_volume; }; // vtable+28

	virtual void SetVolume(MxS32 p_volume); // vtable+2c

	// SYNTHETIC: LEGO1 0x100b8d70
	// MxAudioManager::`scalar deleting destructor'

private:
	void Destroy(MxBool p_fromDestructor);

	static MxS32 g_count;

protected:
	void Init();

	MxS32 m_volume; // 0x2c
};

#endif // MXAUDIOMANAGER_H
