Walks the PEB, finds the loaded modules linked list, gets the address of the module you're after,
then walks the module looking for the routine you want, reads the syscall index from routine address,
and forces a syscall by allocating your custom syscall wrapper. Its only useful to avoid usermode hooks on syscall wrappers


example usage:
```
#include "syscall.h"

class mouseController {
public:
    uint32_t NtUserSendInputIdx;

    mouseController() {
        NtUserSendInputIdx = syscall::getIndex(L"win32u.DLL", "NtUserSendInput");
    }

    BOOLEAN WINAPI NtUserSendInput(UINT cInputs, LPINPUT pInputs, int cbSize) {
        LPVOID call = syscall::allocate_call(NtUserSendInputIdx);
        if (!call) return 0;
        NTSTATUS result = reinterpret_cast<NTSTATUS(NTAPI*)(UINT, LPINPUT, int)>(call)(cInputs, pInputs, cbSize);
        VirtualFree(call, 0, MEM_RELEASE);

        return (result > 0);
    }

    BOOLEAN WINAPI moveAbs(int x, int y) {
        INPUT input;
	    input.type = INPUT_MOUSE;
	    input.mi.mouseData = 0;
	    input.mi.time = 0;
	    input.mi.dx = x * (65536 / GetSystemMetrics(SM_CXSCREEN));
	    input.mi.dy = y * (65536 / GetSystemMetrics(SM_CYSCREEN));
	    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_ABSOLUTE;
	    return NtUserSendInput(1, &input, sizeof(input));
    }
};
```
NOTES:
comparison is case sensitive and the same DLL might be loaded as <name>.dll or <name>.DLL