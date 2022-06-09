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
#include <photon/common/alog.h>
#include <photon/fs/localfs.h>
#include <photon/common/utility.h>
#include <photon/common/uuid.h>
//#include "../overlaybd/filesystem.h"
//#include "../overlaybd/virtual-file.h"
#include "../overlaybd/efile/efile.h"
#include "../overlaybd/tar_file.h"

#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <photon/photon.h>

using namespace std;
using namespace photon::fs;
using namespace EFile;

int usage() {
    static const char msg[] = "overlaybd-efile is a tool to encrypt/decrypt efile. \n"
                              "Usage: overlaybd-efile [options] <src_file> <dst_file>\n"
                              "   -d show debug log.\n"
                              "   -f force encryption. unlink exist <dst_file>.\n"
                              "   -x extract enfile.\n"
                              "example:\n"
                              "- create\n"
                              "   ./overlaybd-efile ./layer0.lsmt ./layer0.lsmtc\n"
                              "- extract\n"
                              "   ./overlaybd-efile -d ./layer0.lsmtc ./layer0.lsmt\n";
    puts(msg);
    return 0;
}

IFileSystem *lfs = nullptr;

int main(int argc, char **argv) {
    log_output_level = 1;
    int ch;
    int op = 0;
    int parse_idx = 1;
    bool rm_old = false;
    bool tar = false;
    CryptOptions opt;
    opt.verify = 1;
    while ((ch = getopt(argc, argv, "fxd:")) != -1) {
        switch (ch) {
        case 'd':
            printf("set log output level: %d\n", log_output_level);
            log_output_level = 0;
            parse_idx++;
            break;
        case 'x':
            op = 1;
            parse_idx++;
            break;
        case 'f':
            parse_idx++;
            rm_old = true;
            break;
        default:
            usage();
            exit(-1);
        }
    }
    lfs = new_localfs_adaptor();
    auto fn_src = argv[parse_idx++];
    auto fn_dst = argv[parse_idx++];
    if (rm_old) {
        lfs->unlink(fn_dst);
    }
    IFileSystem *fs = lfs;
    if (tar) {
        LOG_INFO("create tar header.");
        fs = new_tar_fs_adaptor(lfs);
    }

    int ret = 0;
    CryptArgs args(opt);
    if (op == 0) {
        printf("encrypt file %s as %s\n", fn_src, fn_dst);
        IFile *infile = lfs->open(fn_src, O_RDONLY);
        if (infile == nullptr) {
            LOG_ERROR_RETURN(0, -1, "open source file error.");
        }
        DEFER(delete infile);

        IFile *outfile = fs->open(fn_dst, O_RDWR | O_CREAT | O_EXCL, 0644);
        if (outfile == nullptr) {
            LOG_ERROR_RETURN(0, -1, "open dst file error.");
        }
        DEFER(delete outfile);

        ret = efile_encrypt(infile, outfile, &args);
        if (ret != 0) {
            LOG_ERROR_RETURN(0, -1, "encrypt fail. (err: `, msg: `)", errno, strerror(errno));
        }
        LOG_INFO("encrypt file done.");
        return ret;
    } else {
        printf("decrypt file %s as %s\n", fn_src, fn_dst);

        IFile *infile = fs->open(fn_src, O_RDONLY);
        if (infile == nullptr) {
            LOG_ERROR_RETURN(0, -1, "open source file error.");
        }
        DEFER(delete infile);

        IFile *outfile = lfs->open(fn_dst, O_WRONLY | O_CREAT | O_EXCL, S_IRWXU);
        if (outfile == nullptr) {
            LOG_ERROR_RETURN(0, -1, "open dst file error.");
        }
        DEFER(delete outfile);

        ret = efile_decrypt(infile, outfile);
        if (ret != 0) {
            LOG_ERROR_RETURN(0, -1, "decrypt fail. (err: `, msg: `)", errno, strerror(errno));
        }
        LOG_INFO("decrypt file done.");
        return ret;
    }
}
