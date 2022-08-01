#pragma once
#include <filesystem>
#include <fstream>
#include <vector>
namespace io
{
	std::vector<std::byte> ReadBinaryFile(const std::filesystem::path& path)
	{
		const uint32_t flags = std::ios::in | std::ios::binary | std::ios::ate;
		std::vector<std::byte> file;

		if (!std::filesystem::exists(path))
			return file;

		if (auto stream = std::ifstream{ path, flags })
		{
			file.resize(stream.tellg());
			char* buffer_ptr = reinterpret_cast<char*>(file.data());

			stream.seekg(0, std::ios::beg);
			stream.read(buffer_ptr, file.size());
		}
		return file;
	}
}