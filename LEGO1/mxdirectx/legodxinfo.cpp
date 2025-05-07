#include "legodxinfo.h"

#include <assert.h>
#include <stdio.h> // for vsprintf

// File name validated by BETA10 0x1011cba3; directory unknown

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

// FUNCTION: CONFIG 0x00402730
// FUNCTION: LEGO1 0x1009d030
// FUNCTION: BETA10 0x1011ca54
int LegoDeviceEnumerate::GetDevice(int p_deviceNum, MxDriver*& p_driver, Direct3DDeviceInfo*& p_device)
{
	if (p_deviceNum < 0 || !IsInitialized()) {
		return -1;
	}

	int i = 0;

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++) {
		p_driver = &*it;

		for (list<Direct3DDeviceInfo>::iterator it2 = p_driver->m_devices.begin(); it2 != p_driver->m_devices.end();
			 it2++) {
			if (i == p_deviceNum) {
				p_device = &*it2;
				return 0;
			}
			i++;
		}
	}

	return -1;
}

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

// FUNCTION: BETA10 0x1011cc65
int LegoDeviceEnumerate::BETA_1011cc65(int p_idx, char* p_buffer)
{
	if (p_idx < 0 || !IsInitialized()) {
		return -1;
	}

	int i = 0;
	int j = 0;

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++, i++) {
		MxDriver& driver = *it;
		for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end(); it2++) {

			if (j == p_idx) {
				GUID4 guid;
				memcpy(&guid, &((Direct3DDeviceInfo&) *it2).m_guid, sizeof(GUID4));
				sprintf(p_buffer, "%d 0x%x 0x%x 0x%x 0x%x", i, guid.m_data1, guid.m_data2, guid.m_data3, guid.m_data4);
				return 0;
			}

			j++;
		}
	}

	return -1;
}

// FUNCTION: CONFIG 0x00402860
// FUNCTION: LEGO1 0x1009d0d0
// FUNCTION: BETA10 0x1011cdb4
int LegoDeviceEnumerate::FUN_1009d0d0()
{
	if (!IsInitialized()) {
		return -1;
	}

	if (m_list.size() == 0) {
		return -1;
	}

	int i = 0;
	int j = 0;
	int k = -1;
	int cpu_mmx = SupportsMMX();

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++, i++) {

		MxDriver& driver = *it;
		for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end(); it2++) {
			if ((*it2).m_HWDesc.dcmColorModel) {
				return j;
			}
			else {
				if (cpu_mmx && (*it2).m_HELDesc.dcmColorModel == D3DCOLOR_RGB && i == 0) {
					k = j;
				}
				else if ((*it2).m_HELDesc.dcmColorModel == D3DCOLOR_MONO && i == 0 && k < 0) {
					k = j;
				}
			}

			j++;
		}
	}

	return k;
}

// FUNCTION: CONFIG 0x00402930
// FUNCTION: LEGO1 0x1009d1a0
// FUNCTION: BETA10 0x1011cf54
int LegoDeviceEnumerate::SupportsMMX()
{
	int supports_mmx = SupportsCPUID();

	if (supports_mmx) {
#ifdef _MSC_VER
		__asm {
			push ebx
			mov eax, 0x0            ; EAX=0: Highest Function Parameter and Manufacturer ID
#if _MSC_VER > 1100
			cpuid                   ; Run CPUID
#else
			__emit 0x0f
			__emit 0xa2
#endif
			mov eax, 0x1            ; EAX=1: Processor Info and Feature Bits (unused)
#if _MSC_VER > 1100
			cpuid                   ; Run CPUID
#else
			__emit 0x0f
			__emit 0xa2
#endif
			xor eax, eax            ; Zero EAX register
			bt edx, 0x17            ; Test bit 0x17 (23): MMX instructions (64-bit SIMD) (Store in CF)
			adc eax, eax            ; Add with carry: EAX = EAX + EAX + CF = CF
			pop ebx
			mov supports_mmx, eax   ; Save eax into C variable
		}
#else
		__asm__("movl $0x0, %%eax\n\t"  // EAX=0: Highest Function Parameter and Manufacturer ID
				"cpuid\n\t"             // Run CPUID\n"
				"mov $0x1, %%eax\n\t"   // EAX=1: Processor Info and Feature Bits (unused)
				"cpuid\n\t"             // Run CPUID
				"xorl %%eax, %%eax\n\t" // Zero EAX register
				"btl $0x15, %%edx\n\t"  // Test bit 0x17 (23): MMX instructions (64-bit SIMD) (Store in CF)
				"adc %%eax, %%eax"      // Add with carry: EAX = EAX + EAX + CF = CF
				: "=a"(supports_mmx)    // supports_mmx == EAX
		);
#endif
	}

	return supports_mmx;
}

// FUNCTION: CONFIG 0x00402970
// FUNCTION: LEGO1 0x1009d1e0
// FUNCTION: BETA10 0x1011cf97
int LegoDeviceEnumerate::SupportsCPUID()
{
	int has_cpuid;
#ifdef _MSC_VER
#if defined(_M_IX86)
	__asm {
		xor eax, eax                    ; Zero EAX register
		pushfd                          ; Push EFLAGS register value on the stack
		or dword ptr[esp], 0x200000     ; Set bit 0x200000: Able to use CPUID instruction (Pentium+)
		popfd                           ; Write the updated value into the EFLAGS register
		pushfd                          ; Push EFLAGS register value on the stack (again)
		btr dword ptr[esp], 0x15        ; Test bit 0x15 (21) and reset (set CF)
		adc eax, eax                    ; Add with carry: EAX = EAX + EAX + CF = CF
		popfd                           ; Push EFLAGS register value on the stack (again, and makes sure the stack remains the same)
		mov has_cpuid, eax              ; Save eax into C variable
	}
#elif defined(_M_X64)
	has_cpuid = 1;
#else
	has_cpuid = 0;
#endif
#else
#if defined(__i386__)
	__asm__("xorl %%eax, %%eax\n\t"      // Zero EAX register
			"pushfl\n\t"                 // Push EFLAGS register value on the stack
			"orl $0x200000, (%%esp)\n\t" // Set bit 0x200000: Able to use CPUID instruction (Pentium+)
			"popfl\n\t"                  // Write the updated value into the EFLAGS register
			"pushfl\n\t"                 // Push EFLAGS register value on the stack (again)
			"btrl $0x15, (%%esp)\n\t"    // Test bit 0x15 (21) and reset (set CF)
			"adc %%eax, %%eax\n\t"       // Add with carry: EAX = EAX + EAX + CF = CF
			"popfl" // Push EFLAGS register value on the stack (again, and makes sure the stack remains the same)
			: "=a"(has_cpuid) // has_cpuid == EAX
	);
#elif defined(__x86_64__) || defined(__amd64__)
	has_cpuid = 1;
#else
	has_cpuid = 0;
#endif
#endif
	return has_cpuid;
}

// FUNCTION: CONFIG 0x004029a0
// FUNCTION: LEGO1 0x1009d210
// FUNCTION: BETA10 0x1011cfc4
int LegoDeviceEnumerate::FUN_1009d210()
{
	if (!IsInitialized()) {
		return -1;
	}

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end();) {
		if (!DriverSupportsRequiredDisplayMode(*it)) {
			m_list.erase(it++);
			continue;
		}

		MxDriver& driver = *it;

		for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end();) {
			if (!FUN_1009d3d0(*it2)) {
				driver.m_devices.erase(it2++);
			}
			else {
				it2++;
			}
		}

		if (!driver.m_devices.size()) {
			m_list.erase(it++);
		}
		else {
			it++;
		}
	}

	if (!m_list.size()) {
		return -1;
	}

	return 0;
}

// FUNCTION: CONFIG 0x00402b00
// FUNCTION: LEGO1 0x1009d370
// FUNCTION: BETA10 0x1011d176
unsigned char LegoDeviceEnumerate::DriverSupportsRequiredDisplayMode(MxDriver& p_driver)
{
	for (list<MxDisplayMode>::iterator it = p_driver.m_displayModes.begin(); it != p_driver.m_displayModes.end();
		 it++) {
		if ((*it).m_width == 640 && (*it).m_height == 480) {
			if ((*it).m_bitsPerPixel == 8 || (*it).m_bitsPerPixel == 16) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// FUNCTION: CONFIG 0x00402b60
// FUNCTION: LEGO1 0x1009d3d0
// FUNCTION: BETA10 0x1011d235
unsigned char LegoDeviceEnumerate::FUN_1009d3d0(Direct3DDeviceInfo& p_device)
{
	if (m_list.size() <= 0) {
		return FALSE;
	}

	if (p_device.m_HWDesc.dcmColorModel) {
		if (p_device.m_HWDesc.dwDeviceZBufferBitDepth & DDBD_16 &&
			p_device.m_HWDesc.dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}

	MxDriver& front = m_list.front();
	for (list<Direct3DDeviceInfo>::iterator it = front.m_devices.begin(); it != front.m_devices.end(); it++) {
		if ((&*it) == &p_device) {
			return TRUE;
		}
	}

	return FALSE;
}
