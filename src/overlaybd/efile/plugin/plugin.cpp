#include "plugin.h"
#include <photon/common/alog.h>
#include <memory>

namespace EFile {

class PluginSoftware : public IPlugin {
private:
    char *prk;
    ISoftware *m_software = nullptr;

public:
    uint32_t max_dst_size = 0;
    uint32_t src_blk_size = 0;
    KeyHandle hk = NULL;
    PluginOptions opt;


    int init(const PluginArgs *args) {
        SoftwareOptions sopt;
        sopt.type = args->opt.type;
        sopt.prk = args->prk;
        SoftwareArgs software_args(sopt);
        m_software = create_software(&software_args);

        return 0;
    }

    /*
     * SWK: user key
     * hk: key handle
     * load PUK{SWK}
     */
    int loadKey(char *puk_lek, KeyHandle *hk) {
        int ret = 0;

        CpaCyAesPublicKey publicKey;
        CpaInstanceHandle cyInstHandle;
        /*
        ret = getPuk(cyInstHandle);
        if (ret != 0) {
            LOG_ERROR_RETURN(EINVAL, -1, "Generate public key fail.");
            hk = NULL;
        }*/
        // TBD from cyInstHandle get public key.
        // step2: Use the public key to encrypt SWK return key handle.
        //AesKey aeskey;
        //aeskey.skey = SWK; 
        ret = m_software->loadKey(puk_lek, hk);
        if (ret != 0) {
            LOG_ERROR_RETURN(EINVAL, -1, "Load Key fail.");
            *hk = NULL;
        }

        return ret;
    }

    int encrypt(KeyHandle hk, 
                const unsigned char *src, size_t src_len,
                unsigned char *dst,
                size_t dst_len) override {
        if (dst_len < max_dst_size) {
            LOG_ERROR_RETURN(ENOBUFS, -1, "dst_len should be greater than `", max_dst_size - 1);
        }

        auto ret =  m_software->encrypt(hk, (const unsigned char *)src, src_len, (unsigned char *)dst, src_len);
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
        auto ret = m_software->decrypt(hk, (const unsigned char *)src, src_len, (unsigned char *)dst, dst_len);
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

IPlugin *create_plugin(const PluginArgs *args) {
    IPlugin *rst = nullptr;
    int init_flg = 0;
    const PluginOptions &opt = args->opt;

    // TBD, for different alg with different traver order
    // traverse it accordint to the follow order.
    // 1. check software
    rst = new PluginSoftware;
    if (rst != nullptr) {
        init_flg = ((PluginSoftware *)rst)->init(args);
    } 

    if (init_flg != 0) {
        delete rst;
        return nullptr;
    }



    // 2. check QAT
    /*
    rst = new PluginQAT;
    if (rst != nullptr) {
        init_flg = ((PluginQAT *)rst)->init(args);
    } 

    if (init_flg != 0) {
        delete rst;
        return nullptr;
    }
    */

    return rst;
}

}; // namespace EFile