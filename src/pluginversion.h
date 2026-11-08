/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Walter Correa (CrashDetect Plus)
 */

#ifndef CRASHDETECT_PLUS_PLUGINVERSION_H
#define CRASHDETECT_PLUS_PLUGINVERSION_H

#define CRASHDETECT_PLUS_VERSION_MAJOR 1
#define CRASHDETECT_PLUS_VERSION_MINOR 0
#define CRASHDETECT_PLUS_VERSION_PATCH 0

#define CRASHDETECT_PLUS_VERSION_INT \
  ((CRASHDETECT_PLUS_VERSION_MAJOR << 16) | \
   (CRASHDETECT_PLUS_VERSION_MINOR << 8)  | \
   (CRASHDETECT_PLUS_VERSION_PATCH))

#define CRASHDETECT_PLUS_VERSION_STRING "1.0.0"
#define PROJECT_VERSION_STRING CRASHDETECT_PLUS_VERSION_STRING

#endif // CRASHDETECT_PLUS_PLUGINVERSION_H
