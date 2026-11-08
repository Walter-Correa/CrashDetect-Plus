/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 */

#ifndef CRASHDETECT_PLUS_MINIDUMP_H
#define CRASHDETECT_PLUS_MINIDUMP_H

#include <string>
#include <string_view>
#include "os.h"

namespace minidump {

// Writes a native crash dump (.dmp on Windows) if enabled in Options.
// If base_name is non-empty, it specifies the filename stem without extension
// (e.g. "crashdetect-YYYYMMDD-HHMMSS-PID").
// Returns the UTF-8 path to the generated dump file, or an empty string.
std::string WriteCrashMinidump(const os::Context &context, std::string_view base_name = {});

} // namespace minidump

#endif // !CRASHDETECT_PLUS_MINIDUMP_H
