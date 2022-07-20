/*
   Copyright The Overlaybd Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
#pragma once

#include "cryptor.h"
namespace EFile {
const static size_t MAX_READ_SIZE = 65536; // 64K

extern "C" photon::fs::IFile *efile_open_ro(photon::fs::IFile *file, CryptOptions *popt, bool verify = false,
                                            bool ownership = false);

extern "C" int efile_encrypt(photon::fs::IFile *src_file, photon::fs::IFile *dst_file,
                              const CryptArgs *opt = nullptr);

extern "C" int efile_decrypt(photon::fs::IFile *src_file, photon::fs::IFile *dst_file,
                              const CryptArgs *args);

extern "C" photon::fs::IFile *new_efile_builder(photon::fs::IFile *file,
                                                const CryptArgs *args = nullptr,
                                                bool ownership = false);

// return 1 if file object is a efile.
// return 0 if file object is a normal file.
// otherwise return -1.
extern "C" int is_efile(photon::fs::IFile *file);
} // namespace EFile
