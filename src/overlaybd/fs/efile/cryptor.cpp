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

#include "cryptor.h"
#include "../../alog.h"
#include <memory>

namespace EFile {

typedef enum { KPT, CPU } ProviderType;

class Cryptor_rsa : public ICryptor {
private:
    int getPuk(CpaInstanceHandle cyInstHandle) {
        return 0;
    }

    int checkRSA() {
        return 0;
    }
public:
    uint32_t max_dst_size = 0;
    uint32_t src_blk_size = 0;
    KeyHandle hk = NULL;

    int init(const CryptArgs *args) {
        int ret = 0;
        Credential key;

        // check if RSA is ready
        ret = checkRSA();
        if (ret != 0) {
            LOG_ERROR_RETURN(EINVAL, -1, "RSA software is not ready.");
        } 

        auto opt = &args->opt;
        if (opt == nullptr) {
            LOG_ERROR_RETURN(EINVAL, -1, "CryptOptions* is nullptr.");
        };
        if (opt->type != CryptOptions::RSA) {
            LOG_ERROR_RETURN(EINVAL, -1,
                             "Encryption type invalid. (expected: CryptOptions::RSA)");
        }
        src_blk_size = opt->block_size;
        max_dst_size = RSA_cryptBound(src_blk_size);

        // step1：Generate key-pair and store it.
        ret = RSA_generateKeyPair(&(key.e), &(key.d), &(key.n));
        if (ret != 0) {
            LOG_ERROR_RETURN(EINVAL, -1, "generate Key pair fail.");
        }

        hk = (KeyHandle)&key;

        return 0;
    }

    /*
     * SWK: user key
     * hk: key handle
     */
    int loadKey(Cpa8U *SWK) {
        int ret = 0;
        CpaCyRsaPublicKey publicKey;
        CpaInstanceHandle cyInstHandle;

        ret = getPuk(cyInstHandle);
        if (ret != 0) {
            LOG_ERROR_RETURN(EINVAL, -1, "Generate public key fail.");
        }
        // TBD from cyInstHandle get public key.
        // step2: Use the public key to encrypt SWK return key handle.
        ret = RSA_loadKey(publicKey, SWK, hk);
        if (ret != 0) {
            LOG_ERROR_RETURN(EINVAL, -1, "Load Key fail.");
        }

        return 0;
    }

    int encrypt(const unsigned char *src, size_t src_len, unsigned short int *dst,
                 size_t dst_len) override {
        if (dst_len < max_dst_size) {
            LOG_ERROR_RETURN(ENOBUFS, -1, "dst_len should be greater than `", max_dst_size - 1);
        }

        auto ret = RSA_encrypt(hk, (const unsigned char *)src, (unsigned short int *)dst, src_len, dst_len);
        if (ret < 0) {
            LOG_ERROR_RETURN(EFAULT, -1, "RSA encrypt data failed. (retcode: `).", ret);
        }
        if (ret == 0) {
            LOG_ERROR_RETURN(
                EFAULT, -1,
                "Encryption worked, but was stopped because the *dst couldn't hold all the information.");
        }
        return ret;
    }

    int decrypt(const unsigned short int *src, size_t src_len, unsigned char *dst,
                   size_t dst_len) override {
        if (dst_len < src_blk_size) {
            LOG_ERROR_RETURN(0, -1, "dst_len (`) should be greater than encrypted block size `",
                             dst_len, src_blk_size);
        }
        auto ret = RSA_decrypt(hk, (unsigned char *)dst, (const unsigned short int *)src, dst_len, src_len);
        if (ret < 0) {
            LOG_ERROR_RETURN(EFAULT, -1, "RSA decrypt data failed. (retcode: `)", ret);
        }
        if (ret == 0) {
            LOG_ERROR_RETURN(EFAULT, -1, "RSA decrypt returns 0. THIS SHOULD BE NEVER HAPPEN!");
        }
        LOG_DEBUG("decrypted ` bytes back into ` bytes.", src_len, ret);
        return ret;
    }
};

ICryptor *create_cryptor(const CryptArgs *args) {
    ICryptor *rst = nullptr;
    int init_flg = 0;
    const CryptOptions &opt = args->opt;

    // TBD: read multiple type, use for loop to traverse it.
    switch (opt.type) {

    case CryptOptions::RSA:
        rst = new Cryptor_rsa;
        if (rst != nullptr) {
            init_flg = ((Cryptor_rsa *)rst)->init(args);
        }
        break;

    default:
        LOG_ERROR_RETURN(EINVAL, nullptr, "invalid CryptOptions.");
    }
    if (init_flg != 0) {
        delete rst;
        return nullptr;
    }
    return rst;
}

}; // namespace EFile
