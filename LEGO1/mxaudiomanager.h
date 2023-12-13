#ifndef MXAUDIOMANAGER_H
#define MXAUDIOMANAGER_H

#include "decomp.h"
#include "mxmediamanager.h"

// VTABLE: LEGO1 0x100dc6e0
class MxAudioManager : public MxMediaManager {
public:
	MxAudioManager();
	virtual ~MxAudioManager() override;

	virtual MxResult InitPresenters() override; // vtable+14
	virtual void Destroy() override;            // vtable+18
	virtual MxS32 GetVolume();                  // vtable+28
	virtual void SetVolume(MxS32 p_volume);     // vtable+2c

private:
	void Destroy(MxBool p_fromDestructor);

	static MxS32 g_count;

protected:
	void Init();

	MxS32 m_volume; // 0x2c
};

#endif // MXAUDIOMANAGER_H
