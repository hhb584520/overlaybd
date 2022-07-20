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
#include <photon/common/alog.h>
#include <memory>

#define AES_MAX_INPUT_SIZE        0x7E000000   /* 2 113 929 216 bytes */
int CryptBound(int isize) {

    if ((unsigned)isize > (unsigned)AES_MAX_INPUT_SIZE) {
        return 0;
    }
    else {
        return ((isize) + ((isize)/255) + 16);
    }
}

namespace EFile {

class Cryptor_aes : public ICryptor {
private:
    IPlugin *m_plugin = nullptr;

public:
    uint32_t max_dst_size = 0;
    uint32_t src_blk_size = 0;

    int init(const CryptArgs *args) {
        int ret = 0;

        auto opt = &args->opt;
        if (opt == nullptr) {
            LOG_ERROR_RETURN(EINVAL, -1, "CryptOptions* is nullptr.");
        };

        src_blk_size = opt->block_size;
        max_dst_size = CryptBound(src_blk_size);

        PluginOptions popt;
        popt.prk = args->prk;  // private key
        popt.type = CryptOptions::AES;
        PluginArgs plugin_args(popt);
        
        m_plugin = create_plugin(&plugin_args);

        return 0;
    }

    /*
     * puk_lek: the lek is wrapped by puk.
     * return 
     *   hk: KeyHandle
     */
    int loadKey(char *puk_lek, KeyHandle *hk) {
        int ret = 0;

        // TBD from cyInstHandle get public key.
        // step2: Use the public key to encrypt SWK return key handle.
        ret = m_plugin->loadKey(puk_lek, hk);
        if (ret != 0) {
            LOG_ERROR_RETURN(EINVAL, -1, "Load Key fail.");
            hk = NULL;
        }

        return ret;
    }

    int encrypt(KeyHandle hk,
                const unsigned char *src,
                size_t src_len,
                unsigned char *dst,
                size_t dst_len) override {
        if (dst_len < max_dst_size) {
            LOG_ERROR_RETURN(ENOBUFS, -1, "dst_len should be greater than `", max_dst_size - 1);
        }

        auto ret = m_plugin->decrypt(hk, (const unsigned char *)src, src_len, (unsigned char *)dst, dst_len);
        if (ret < 0) {
            LOG_ERROR_RETURN(EFAULT, -1, "AES encrypt data failed. (retcode: `).", ret);
        }
        if (ret == 0) {
            LOG_ERROR_RETURN(
                EFAULT, -1,
                "Encryption worked, but was stopped because the *dst couldn't hold all the information.");
        }
        return ret;
    }

    int decrypt(KeyHandle hk,
                const unsigned char *src,
                size_t src_len,
                unsigned char *dst,
                size_t dst_len) override {
        if (dst_len < src_blk_size) {
            LOG_ERROR_RETURN(0, -1, "dst_len (`) should be greater than encrypted block size `",
                             dst_len, src_blk_size);
        }
        auto ret = m_plugin->decrypt(hk, (const unsigned char *)src, src_len, (unsigned char *)dst, dst_len);
        if (ret < 0) {
            LOG_ERROR_RETURN(EFAULT, -1, "AES decrypt data failed. (retcode: `)", ret);
        }
        if (ret == 0) {
            LOG_ERROR_RETURN(EFAULT, -1, "AES decrypt returns 0. THIS SHOULD BE NEVER HAPPEN!");
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

    case CryptOptions::AES:
        rst = new Cryptor_aes;
        if (rst != nullptr) {
            init_flg = ((Cryptor_aes *)rst)->init(args);
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
