#include "Util.h"

NTSTATUS DriverEntry(PVOID Kernel)
{
    Kernel = Util::GetKernelBase();
    Log("Ntoskrnl: 0x%p", Kernel);

    auto DbgkForwardExceptionPattern = (uint64_t)Util::FindPattern(
        uint64_t(Kernel), "PAGE", "\x65\x48\x8B\x04\x25\x88\x00\x00\x00\x8B\x88\x00\x00\x00\x00\xF6\xC1\x04",
        "xxxxxx???xx????xxx");

    Log("DbgkForwardExceptionPattern: 0x%p", DbgkForwardExceptionPattern);

    if (DbgkForwardExceptionPattern)
    {
        for (size_t i = 0; *(uint8_t *)(DbgkForwardExceptionPattern + i) != 0xC3; i++)
        {
            if (*(uint8_t *)(DbgkForwardExceptionPattern + i) == 0x74)
            {
                _disable();
                Util::disable_wp();

                *(uint8_t *)(DbgkForwardExceptionPattern + i) = 0xEB;
                *(uint8_t *)(DbgkForwardExceptionPattern + i + 1) = 0x04;

                Util::enable_wp();
                _enable();
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}
