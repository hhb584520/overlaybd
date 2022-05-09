#include "lz4.h"
#include "lz4-qat.h"
#include <unistd.h>

#define sleeptime 100

int gDebugParam = 1;


int qat_init(LZ4_qat_param *pQat) {
    int32_t status = 0;

    return (int)status;
}

int qat_uninit(LZ4_qat_param *pQat) {
    int32_t status = 0;

    return status;
}

// compression operation.


LZ4LIB_API int LZ4_compress_qat(LZ4_qat_param *pQat, const unsigned char *const raw_data[],
                                size_t steplist[], unsigned char *compressed_data[],
                                size_t compressed_len[], ssize_t cur) {
    int32_t status = 0;

    return status;
}

LZ4LIB_API int LZ4_decompress_qat(LZ4_qat_param *pQat, const char *source, char *dest,
                                  int compressedSize, int maxDecompressedSize) {
    int32_t status = 0;

    return status;
}
