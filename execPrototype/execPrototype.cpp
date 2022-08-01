#include "Windows.h"
#include <iostream>
#include "PortableExecutable.h"
#include <psapi.h>

#include <debugapi.h>

PROCESS_INFORMATION StartServer(const std::filesystem::path& path, int argc, char* argv[])
{
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process_info;

	ZeroMemory(&startup_info, sizeof(startup_info));
	ZeroMemory(&process_info, sizeof(process_info));
	startup_info.cb = sizeof(startup_info);

	if (!CreateProcess(path.c_str(), nullptr, nullptr, nullptr, true, CREATE_SUSPENDED, nullptr, nullptr, &startup_info, &process_info))
	{
		CloseHandle(process_info.hProcess);
		CloseHandle(process_info.hThread);
		std::cout << "[*] Unable to create Ark Server Process.\n";
	}
	return process_info;

}


void inject_DLL(const std::filesystem::path& path, HANDLE handle)
{
	std::size_t written = 0;
	std::size_t bytes = (path.string().size() + 1) * sizeof(wchar_t);
	auto memory = VirtualAllocEx(handle, 0, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (memory)
	{
		WriteProcessMemory(handle, memory, path.c_str(), bytes, &written);
		std::cout << "[*] Wrote " << written << " bytes into target for loading.\n";
		auto myLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");


		HANDLE thread = CreateRemoteThread(handle, 0, 0,
			(LPTHREAD_START_ROUTINE)myLoadLibrary, memory, 0, 0);
		if (!thread)
		{
			std::cout << "thread creation failed.....\n";
		}
		std::cout << "thread created...\n";
		WaitForSingleObject(thread, INFINITE);
		VirtualFreeEx(handle, memory, bytes, MEM_RELEASE);
	}


}

void ffff(int argc, char* argv[])
{
	const std::byte ep_loop[] = {std::byte(0xEB), std::byte(0xFE)};
	std::byte ep_original[] = { std::byte(0x0), std::byte(0x0) };

	const std::wstring game = L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\ARK Survival Evolved Dedicated Server\\ShooterGame\\Binaries\\Win64\\ShooterGameServer.exe";

	std::size_t server_ep_rva = PortableExecutable::FromFile(game).NTHeader().OptionalHeader.AddressOfEntryPoint;
	std::size_t server_image_base = 0;
	std::size_t server_ep_absolute = 0;

	const auto process_info = StartServer(game, argc, argv);

	DEBUG_EVENT debug_event {};

	if (!DebugActiveProcess(process_info.dwProcessId))
	{
		std::cout << "[*] Unable to attach debugger.\n";
		return;
	}
	std::cout << "[*] Attached debugger.\n";

	if (!DebugSetProcessKillOnExit(false))
		std::cout << "[*] Unable to preserve process on detach.\n";

	do
	{
		std::cout << "[*] Waiting for debugger event.\n";
		WaitForDebugEvent(&debug_event, INFINITE);
		std::cout << "[*] Recieved event, code: " << debug_event.dwDebugEventCode << ".\n";
		ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);

	} while (debug_event.dwDebugEventCode != 3); //3 = create process.

	std::cout << "[*] Detaching debugger.\n";
	if (!DebugActiveProcessStop(debug_event.dwProcessId))
		std::cout << "[*] Unable to detach debugger.\n";

	server_image_base = reinterpret_cast<std::size_t>(debug_event.u.CreateProcessInfo.lpBaseOfImage);

	server_ep_absolute = server_image_base + server_ep_rva;

	std::cout << std::hex << "[*] Image Base: " << server_image_base << "\n[*] Entry Point RVA: " << server_ep_rva << "\n[*] Entry Point Absolute: " << server_ep_absolute << "\n" << std::dec;

	DWORD lpflOldProtect = 0;
	std::size_t rpmwpm = 0;

	if (!VirtualProtectEx(process_info.hProcess, reinterpret_cast<void*>(server_ep_absolute), 2, PAGE_EXECUTE_READWRITE, &lpflOldProtect))
		std::cout << "[*] VirtualProtectEx failed.\n";

	if (!ReadProcessMemory(process_info.hProcess, reinterpret_cast<void*>(server_ep_absolute), ep_original, 2, &rpmwpm))
		std::cout << "[*] ReadProcessMemory failed.\n";

	std::cout << "[*] Read " << rpmwpm << " bytes.\n";


	if(!WriteProcessMemory(process_info.hProcess, reinterpret_cast<void*>(server_ep_absolute), ep_loop, 2, &rpmwpm))
		std::cout << "[*] WriteProcessMemory failed.\n";

	std::cout << "[*] Wrote " << rpmwpm << " bytes.\n";

	ResumeThread(process_info.hThread);

	CONTEXT context;
	ZeroMemory(&context, sizeof(context));

	GetThreadContext(process_info.hThread, &context);

	for (unsigned int i = 0; i < 50000 && context.Rip != server_ep_absolute; ++i)
	{
		std::cout << "[*] RIP is currently " << std::hex << context.Rip << std::dec << ".\n";
		//Sleep(1);

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(process_info.hThread, &context);
	}
	if (context.Rip != server_ep_absolute)
		std::cout << "[*] RIP != EP after 50 * 100ms.\n";
	else
		std::cout << "[*] RIP = EP.\n";

	std::cout << "[*] Injecting API\n";
	inject_DLL(L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\ARK Survival Evolved Dedicated Server\\ShooterGame\\Binaries\\Win64\\asi.dll", process_info.hProcess);

	SuspendThread(process_info.hThread);
	if(!WriteProcessMemory(process_info.hProcess, reinterpret_cast<void*>(server_ep_absolute), ep_original, 2, &rpmwpm))
		std::cout << "[*] WriteProcessMemory failed.\n";
	std::cout << "[*] Wrote " << rpmwpm << " bytes.\n";



	ResumeThread(process_info.hThread);

	WaitForSingleObject(process_info.hProcess, INFINITE);

	CloseHandle(process_info.hThread);
	CloseHandle(process_info.hProcess);

}

int main(int argc, char* argv[]) {

	ffff(argc, argv);
	return 0;
}