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
#ifndef __CRYPTOR_H__
#define __CRYPTOR_H__

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include "aes/aes.h"

namespace photon {
    namespace fs {
        class IFile;
    }
}

namespace EFile {

struct Credential {
    i16_t e;
    i16_t d;
    i16_t n;
};

/* CryptOptions will write into file */
class CryptOptions {
public:
    const static uint8_t AES = 0;
    const static uint32_t DEFAULT_BLOCK_SIZE = 4096; // 8192;//32768;

    uint32_t block_size = DEFAULT_BLOCK_SIZE;
    uint8_t type = AES; // algorithm
    uint8_t use_dict = 0;
    uint32_t args = 0; // reserve;
    uint32_t dict_size = 0;
    uint8_t verify = 0;

    CryptOptions(uint8_t type = AES, uint32_t block_size = DEFAULT_BLOCK_SIZE,
                    uint8_t verify = 0)
        : block_size(block_size), type(type), verify(verify) {
    }
};

class CryptArgs {
public:
    photon::fs::IFile *fdict = nullptr;
    std::unique_ptr<unsigned char[]> dict_buf = nullptr;
    CryptOptions opt;

    CryptArgs(const CryptOptions &opt, photon::fs::IFile *dict = nullptr,
                 unsigned char *dict_buf = nullptr)
        : fdict(dict), dict_buf(dict_buf), opt(opt) {
        if (fdict || dict_buf) {
            this->opt.use_dict = 1;
        }
    };
};

class ICryptor {
public:
    virtual ~ICryptor(){};
                       
    /*
     * SWK: user key
     * hk: key handle
     * 
     *  success return 0.
        return -1 when error occurred.
    */
    virtual int loadKey(char *SWK) = 0;

    /*
        return encrypted buffer size.
        return -1 when error occurred.
    */
    virtual int encrypt(const unsigned char *src,
                        size_t src_len,
                        unsigned char *dst,
                        size_t dst_len) = 0;

    /*
        return decrypted buffer size.
        return -1 when error occurred.
    */
    virtual int decrypt(const unsigned char *src,
                        size_t src_len,
                        unsigned char *dst,
                        size_t dst_len) = 0;


};

extern "C" ICryptor *create_cryptor(const CryptArgs *args);
} // namespace EFile

#endif
