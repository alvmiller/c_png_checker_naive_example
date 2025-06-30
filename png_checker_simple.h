
/**
 * @file
 * @brief Simple PNG format checker (additional checks needed by uPNG,
 *        without additional memory allocation, external independent module,
 *        acc. to Portable Network Graphics (PNG) Specification (Second Edition))
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    PNG_CHECKER_RES_SUCCESS,
    PNG_CHECKER_RES_ERROR_GENERIC,
    PNG_CHECKER_RES_ERROR_WRONG_SIZE,
    PNG_CHECKER_RES_ERROR_BAD_PARAMETERS,
    PNG_CHECKER_RES_ERROR_BAD_SIGNATURE,
    PNG_CHECKER_RES_ERROR_BAD_IHDR_SIZE,
    PNG_CHECKER_RES_ERROR_BAD_IHDR_FORMAT,
    PNG_CHECKER_RES_ERROR_BAD_PIC_SIZES,
    PNG_CHECKER_RES_ERROR_BAD_COMP_METH,
    PNG_CHECKER_RES_ERROR_BAD_FILT_METH,
    PNG_CHECKER_RES_ERROR_BAD_INT_METH,
    PNG_CHECKER_RES_ERROR_BAD_COLOR,
    PNG_CHECKER_RES_ERROR_BAD_CRC32,
    PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW,
    PNG_CHECKER_RES_ERROR_BAD_STATE,
    PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE,
    PNG_CHECKER_RES_ERROR_NOT_IMPLEMENTED,
    PNG_CHECKER_RES_ERROR_CHUNK_UNKNOWN_TYPE,
    PNG_CHECKER_RES_ERROR_BAD_CHUNK_TYPE,
    PNG_CHECKER_RES_ERROR_BAD_IHDR_CHUNK_TYPE,
    PNG_CHECKER_RES_ERROR_BAD_IEND_CHUNK_TYPE,
    PNG_CHECKER_RES_ERROR_BAD_PLTE_CHUNK_TYPE,
    PNG_CHECKER_RES_ERROR_BAD_FORMAT,
} png_check_res_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @bfief Simple check PNG format.
 *
 * @param[in] pic_buffer - input buffer with PNG picture.
 * @param[in] pic_buffer_size -  buffer with PNG picture size.
 *
 * @return PNG_CHECKER_RES_SUCCESS in case of success.
 * @return error code in case of errors.
 */
png_check_res_t png_check(const uint8_t *pic_buffer, size_t pic_buffer_size);

#ifdef __cplusplus
}
#endif
