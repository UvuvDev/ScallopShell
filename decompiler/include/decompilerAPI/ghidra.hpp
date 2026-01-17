#pragma once
#include "filesystem"

int runHeadless(const std::filesystem::path& ghidraHeadlessPath, const std::filesystem::path& elfPath, std::string projectName, std::string projectSubdir);