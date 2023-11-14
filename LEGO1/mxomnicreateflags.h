#ifndef MXOMNICREATEFLAGS_H
#define MXOMNICREATEFLAGS_H

#include "mxtypes.h"

class MxOmniCreateFlags {
public:
	enum LowFlags {
		Flag_CreateObjectFactory = 0x01,
		Flag_CreateVariableTable = 0x02,
		Flag_CreateTickleManager = 0x04,
		Flag_CreateNotificationManager = 0x08,
		Flag_CreateVideoManager = 0x10,
		Flag_CreateSoundManager = 0x20,
		Flag_CreateMusicManager = 0x40,
		Flag_CreateEventManager = 0x80
	};

	enum HighFlags {
		Flag_CreateTimer = 0x02,
		Flag_CreateStreamer = 0x04
	};

	__declspec(dllexport) MxOmniCreateFlags();

	inline const MxBool CreateObjectFactory() const { return this->m_flags1 & Flag_CreateObjectFactory; }
	inline const MxBool CreateVariableTable() const { return this->m_flags1 & Flag_CreateVariableTable; }
	inline const MxBool CreateTickleManager() const { return this->m_flags1 & Flag_CreateTickleManager; }
	inline const MxBool CreateNotificationManager() const { return this->m_flags1 & Flag_CreateNotificationManager; }
	inline const MxBool CreateVideoManager() const { return this->m_flags1 & Flag_CreateVideoManager; }
	inline const MxBool CreateSoundManager() const { return this->m_flags1 & Flag_CreateSoundManager; }
	inline const MxBool CreateMusicManager() const { return this->m_flags1 & Flag_CreateMusicManager; }
	inline const MxBool CreateEventManager() const { return this->m_flags1 & Flag_CreateEventManager; }

	inline const MxBool CreateTimer() const { return this->m_flags2 & Flag_CreateTimer; }
	inline const MxBool CreateStreamer() const { return this->m_flags2 & Flag_CreateStreamer; }

	inline void CreateObjectFactory(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateObjectFactory : this->m_flags1 & ~Flag_CreateObjectFactory);
	}
	inline void CreateVariableTable(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateVariableTable : this->m_flags1 & ~Flag_CreateVariableTable);
	}
	inline void CreateTickleManager(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateTickleManager : this->m_flags1 & ~Flag_CreateTickleManager);
	}
	inline void CreateNotificationManager(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateNotificationManager
					   : this->m_flags1 & ~Flag_CreateNotificationManager);
	}
	inline void CreateVideoManager(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateVideoManager : this->m_flags1 & ~Flag_CreateVideoManager);
	}
	inline void CreateSoundManager(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateSoundManager : this->m_flags1 & ~Flag_CreateSoundManager);
	}
	inline void CreateMusicManager(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateMusicManager : this->m_flags1 & ~Flag_CreateMusicManager);
	}
	inline void CreateEventManager(MxBool b)
	{
		this->m_flags1 =
			(b == TRUE ? this->m_flags1 | Flag_CreateEventManager : this->m_flags1 & ~Flag_CreateEventManager);
	}

	inline void CreateTimer(MxBool b)
	{
		this->m_flags2 = (b == TRUE ? this->m_flags2 | Flag_CreateTimer : this->m_flags2 & ~Flag_CreateTimer);
	}
	inline void CreateStreamer(MxBool b)
	{
		this->m_flags2 = (b == TRUE ? this->m_flags2 | Flag_CreateStreamer : this->m_flags2 & ~Flag_CreateStreamer);
	}

private:
	unsigned char m_flags1;
	unsigned char m_flags2;
};

#endif // MXOMNICREATEFLAGS_H
