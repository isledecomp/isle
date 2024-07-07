#include "legodxinfo.h"

#include <assert.h>
#include <stdio.h> // for vsprintf

// File name validated by BETA10 0x1011cba3; directory unknown

// FUNCTION: CONFIG 0x004027d0
// FUNCTION: BETA10 0x1011cb70
int LegoDeviceEnumerate::FormatDeviceName(char* p_buffer, const MxDriver* p_ddInfo, const Direct3DDeviceInfo* p_d3dInfo)
	const
{
	int number = 0;
	assert(p_ddInfo && p_d3dInfo);

	for (list<MxDriver>::const_iterator it = m_list.begin(); it != m_list.end(); it++, number++) {
		if (&(*it) == p_ddInfo) {
			GUID4 guid;
			memcpy(&guid, p_d3dInfo->m_guid, sizeof(GUID4));

			sprintf(p_buffer, "%d 0x%x 0x%x 0x%x 0x%x", number, guid.m_data1, guid.m_data2, guid.m_data3, guid.m_data4);
			return 0;
		}
	}

	return -1;
}

// FUNCTION: CONFIG 0x00402560
// FUNCTION: LEGO1 0x1009ce60
// FUNCTION: BETA10 0x1011c7e0
int LegoDeviceEnumerate::ParseDeviceName(const char* p_deviceId)
{
	if (!IsInitialized()) {
		return -1;
	}

	int unknown = -1;
	int num = -1;
	int hex[4];

	if (sscanf(p_deviceId, "%d 0x%x 0x%x 0x%x 0x%x", &num, &hex[0], &hex[1], &hex[2], &hex[3]) != 5) {
		return -1;
	}

	if (num < 0) {
		return -1;
	}

	GUID guid;
	memcpy(&guid, hex, sizeof(guid));

	int result = ProcessDeviceBytes(num, guid);

	if (result < 0) {
		result = ProcessDeviceBytes(-1, guid);
	}

	return result;
}

// FUNCTION: CONFIG 0x00402620
// FUNCTION: LEGO1 0x1009cf20
// FUNCTION: BETA10 0x1011c8b3
int LegoDeviceEnumerate::ProcessDeviceBytes(int p_deviceNum, GUID& p_guid)
{
	if (!IsInitialized()) {
		return -1;
	}

	int i = 0;
	int j = 0;

	static_assert(sizeof(GUID4) == sizeof(GUID), "Equal size");

	GUID4 deviceGuid;
	memcpy(&deviceGuid, &p_guid, sizeof(GUID4));

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++, i++) {
		if (p_deviceNum >= 0 && p_deviceNum < i) {
			return -1;
		}

		GUID4 compareGuid;
		MxDriver& driver = *it;
		for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end(); it2++) {
			Direct3DDeviceInfo& md3d = *it2;
			assert(md3d.m_guid);

			memcpy(&compareGuid, md3d.m_guid, sizeof(GUID4));

			if (GUID4::Compare(compareGuid, deviceGuid) && i == p_deviceNum) {
				return j;
			}

			j++;
		}
	}

	return -1;
}
