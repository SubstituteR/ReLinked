#pragma once
#define WIN32_LEAN_AND_MEAN
#include "Windows.h"
#include <string>
#include <filesystem>

#include "io.h"


class PortableExecutable
{
	IMAGE_DOS_HEADER dos_header_;
	IMAGE_NT_HEADERS nt_header_;

public:

	constexpr const IMAGE_DOS_HEADER& DosHeader() { return dos_header_; }
	constexpr const IMAGE_NT_HEADERS& NTHeader() { return nt_header_; }

	static PortableExecutable FromFile(const std::filesystem::path& path)
	{
		PortableExecutable instance{};

		auto file = io::ReadBinaryFile(path);

		if (file.size() == 0)
			return instance;
	
		memcpy(&instance.dos_header_, file.data(), sizeof(IMAGE_DOS_HEADER));

		if (instance.dos_header_.e_lfanew != 0)
			memcpy(&instance.nt_header_, file.data() + instance.dos_header_.e_lfanew, sizeof(IMAGE_NT_HEADERS));

		return instance;
	}
};