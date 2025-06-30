/**
 * @file
 * @brief Simple PNG format checker
 *        (without additional memory heap allocation, thread-safe, external independent module).
 *        Acc. to Portable Network Graphics (PNG) Specification (Second Edition)
 */

#include "png_checker.h"

#include <endian.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <stdio.h>

/*************************************************************************************************/

/* PNG format:
 *
 * Header Signature    0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A
 * IHDR                    |      | Width              [4] |
 *                         |      | Height             [4] |
 *                         |      | Bit depth          [1] |
 *                     len | IHDR | Colour type        [1] | CRC
 *                         |      | Compression method [1] |
 *                         |      | Filter method      [1] |
 *                         |      | Interlace method   [1] |
 * ...
 * tEXt chunk          len | tEXt | data                   | CRC
 * ...
 * IDAT chunk          len | IDAT | data                   | CRC
 * ...
 * IEND chunk            0 | IEND |                        | CRC
 */

/*************************************************************************************************/

/* PNG Signature Bytes:
 * 137 (0x89) - A byte with its most significant bit set (8-bit character)
 *  80 (0x50) - P
 *  78 (0x4E) - N
 *  71 (0x47) - G
 *  13 (0x0D) - Carriage-return (CR) character, CTRL-M or ^M
 *  10 (0x0A) - Line-feed (LF) character, CTRL-J or ^J
 *  26 (0x1A) - CTRL-Z or ^Z
 *  10 (0x0A) - Line-feed (LF) character, CTRL-J or ^J
 */
static const uint8_t png_header_signature[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

/*************************************************************************************************/

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define PNG_SIGNATURE_POS (UINT32_C(0))

#define PNG_IHDR_POS (UINT32_C(ARRAY_SIZE(png_header_signature))) /* 8 */
#define PNG_IHDR_DATA_WIDTH_POS (UINT32_C(0))
#define PNG_IHDR_DATA_HEIGHT_POS (UINT32_C(4))
#define PNG_IHDR_DATA_BIT_DEPTH_POS (UINT8_C(8))
#define PNG_IHDR_DATA_COLOR_TYPE_POS (UINT8_C(9))
#define PNG_IHDR_DATA_COMPRESSION_METHOD_POS (UINT8_C(10))
#define PNG_IHDR_DATA_FILTER_METHOD_POS (UINT8_C(11))
#define PNG_IHDR_DATA_INTERLACE_METHOD_POS (UINT8_C(12))

#define PNG_CHUNK_TAG_TYPE_SIZE (UINT32_C(4))
#define PNG_CHUNK_TAG_LEN_SIZE (UINT32_C(4))
#define PNG_CHUNK_TAG_CRC32_SIZE (UINT32_C(4))
#define PNG_HEADER_SIGNATURE_SIZE (UINT32_C(8))
#define PNG_IHDR_DATA_SIZE (UINT32_C(13))
#define PNG_IHDR_CRC32_DATA_SIZE (UINT32_C(17))
#define PNG_INTERLACE_FILTER_PADDING_SIZE (7)

#define PNG_CHUNK_TYPE_POS (4) /* after len bytes */

#define PNG_MIN_CHUNK_SIZE (PNG_CHUNK_TAG_LEN_SIZE \
                          + PNG_CHUNK_TAG_TYPE_SIZE \
                          + PNG_CHUNK_TAG_CRC32_SIZE) /* 12 */
#define PNG_FULL_HEADER_SIZE (PNG_HEADER_SIGNATURE_SIZE \
                            + PNG_IHDR_DATA_SIZE \
                            + PNG_MIN_CHUNK_SIZE) /* 33 */

#define BASIC_FILTER_METHOD (UINT32_C(0))
#define BASIC_COMPRESSION_METHOD (UINT32_C(0))
#define MAX_INTERLACE_METHOD (UINT32_C(1)) /* Could be 0 and 1,
                                            * so no need to use array for checking */
#define BYTES_PER_CHANNEL_COLOR (UINT8_C(CHAR_BIT)) /* Bit pointer with 8-bit color */
#define PNG_IEND_CHUNK_TAG (UINT32_C(0))

/*
 * An 8-byte file signature.
 * A 13-byte IHDR chunk containing the image header, plus 12 bytes chunk overhead.
 * A 16-byte IDAT chunk containing the image data, plus 12 bytes chunk overhead.
 * A 0-byte IEND chunk marking the end of the file, plus 12 bytes chunk overhead.
 * 73 bytes
*/
/* Signature (8) + IHDR (25) + IDAT (12, without internal data) + IEND (12, min) */
#define MIN_PNG_FILE_SIZE (UINT8_C(PNG_FULL_HEADER_SIZE \
                                 + PNG_MIN_CHUNK_SIZE \
                                 + PNG_MIN_CHUNK_SIZE)) /* 57 */

#define PNG_HEADER_SIGNATURE_PTR(buff) ((buff) + PNG_SIGNATURE_POS)
#define PNG_IHDR_PTR(buff) ((buff) + PNG_IHDR_POS)
#define PNG_CHUNK_DATA_PTR(chunk) ((chunk) + PNG_CHUNK_TAG_LEN_SIZE + PNG_CHUNK_TAG_TYPE_SIZE)
#define PNG_IHDR_PIC_WIDTH_PTR(ihdr) (PNG_CHUNK_DATA_PTR(ihdr) + PNG_IHDR_DATA_WIDTH_POS)
#define PNG_IHDR_PIC_HEIGHT_PTR(ihdr) (PNG_CHUNK_DATA_PTR(ihdr) + PNG_IHDR_DATA_HEIGHT_POS)
#define PNG_IHDR_BIT_DEPTH_PTR(ihdr) (PNG_CHUNK_DATA_PTR(ihdr) + PNG_IHDR_DATA_BIT_DEPTH_POS)
#define PNG_IHDR_COLOR_TYPE_PTR(ihdr) (PNG_CHUNK_DATA_PTR(ihdr) + PNG_IHDR_DATA_COLOR_TYPE_POS)
#define PNG_IHDR_COMPRESSION_METHOD_PTR(ihdr) (PNG_CHUNK_DATA_PTR(ihdr) \
                                             + PNG_IHDR_DATA_COMPRESSION_METHOD_POS)
#define PNG_IHDR_FILTER_METHOD_PTR(ihdr) (PNG_CHUNK_DATA_PTR(ihdr) \
                                        + PNG_IHDR_DATA_FILTER_METHOD_POS)
#define PNG_IHDR_INTERLACE_METHOD_PTR(ihdr) (PNG_CHUNK_DATA_PTR(ihdr) \
                                           + PNG_IHDR_DATA_INTERLACE_METHOD_POS)
#define PNG_CRC32_VALUE_PTR(chunk, data_size) ((chunk) \
                                             + PNG_CHUNK_TAG_LEN_SIZE \
                                             + PNG_CHUNK_TAG_TYPE_SIZE \
                                             + (data_size))
#define PNG_FIRST_CHUNK_PTR(buff) ((buff) + PNG_FULL_HEADER_SIZE)
#define PNG_CHUNK_TYPE_PTR(chunk) ((chunk) + PNG_CHUNK_TYPE_POS)

#define PNG_BUFFER_STEP_DISTANCE(ptr_start, ptr_end) \
                                ((size_t) ((uint8_t *) (ptr_end) - (uint8_t *) (ptr_start)))

/* Convert Big Endian to Big Endian */
#define CONVERT_32BIT_VALUE_BE_BE(ptr) ( (uint32_t) \
                                         ((((ptr)[3] & 0xFF) << 24) \
                                        | (((ptr)[2] & 0xFF) << 16) \
                                        | (((ptr)[1] & 0xFF) << 8) \
                                        | ((ptr)[0] & 0xFF) ) )
#define GET_32BIT_VALUE(ptr) (CONVERT_32BIT_VALUE_BE_BE(ptr))

#define PNG_CHUNK_PLTE_DIV_DATA_SIZE (UINT8_C(3))
#define PNG_CHUNK_PLTE_MAX_COLOR_SET (UINT16_C(256))
#define PNG_CHUNK_TRNS_GREY_DATA_SIZE (UINT8_C(2))
#define PNG_CHUNK_TRNS_RGB_DATA_SIZE (UINT8_C(6))
#define PNG_CHUNK_BKGD_GREY_GREYA_DATA_SIZE (UINT8_C(2))
#define PNG_CHUNK_BKGD_RGB_RGBA_DATA_SIZE (UINT8_C(6)) /* R G B (3) * 2 bytes */
#define PNG_CHUNK_BKGD_PALETTE_DATA_SIZE (UINT8_C(1))

/*************************************************************************************************/

typedef struct __attribute__((packed, aligned(sizeof(uint32_t)))) ihdr_data_chunk_struct {
    uint32_t width;
    uint32_t height;
    uint8_t bit_depth;
    uint8_t color_type;
    uint8_t compression_method;
    uint8_t filter_method;
    uint8_t interlace_method;
} ihdr_chunk_struct_t;

/* Acc. to 11.2.2 IHDR Image header
 * (Table 11.1 - Allowed combinations of colour type and bit depth */
typedef enum {
    PNG_COLOR_GREY = UINT8_C(0), /* Bit depths: 1, 2, 4, 8, 16
                                    (each pixel is a grayscale sample) */
    PNG_COLOR_RGB = UINT8_C(2), /* Bit depths: 8, 16 (each pixel is an R, G, B triple) */
    PNG_COLOR_PALETTE = UINT8_C(3), /* Bit depths: 1, 2, 4, 8 (each pixel is a palette index,
                                       a PLTE chunk must appear) */
    PNG_COLOR_GREYA = UINT8_C(4), /* Bit depths: 8, 16 (each pixel is a grayscale sample,
                                     followed by an alpha sample) */
    PNG_COLOR_RGBA = UINT8_C(6), /* Bit depths: 8, 16 (each pixel is an R, G, B triple,
                                    followed by an alpha sample) */
} png_color_t;

/* Critical chunks:
 * - (IHDR | 73 72 68 82 | 0x49 0x48 0x44 0x52): First chunk (IHDR): the image header chunk
 * - (IEND | 73 69 78 68 | 0x49 0x45 0x4E 0x44): Last chunk, it marks the end of the datastream,
 *                                               the chunk's data field is empty
 * - (IDAT | 73 68 65 84 | 0x49 0x44 0x41 0x54): Chunk contains the actual image data and contains
 *                                               the output datastream of the compression algorithm
 * - (PLTE | 80 76 84 69 | 0x50 0x4c 0x54 0x45): Chunk contains from 1 to 256 palette entries,
 *                                               each a three-byte series of RGB
 *
 * Ancillary chunks:
 * - Transparency information:
 * -- (tRNS | 116 82 78 83 | 0x74 0x52 0x4e 0x53): Chunk specifies that the image uses simple
 *                                                 transparency: either alpha values associated
 *                                                 with palette entries (for indexed-color images)
 *                                                 or a single transparent color
 *                                                 (for grayscale and truecolor images)
 * - Colour space information:
 * -- (gAMA | 103 65 77 65 | 0x67 0x41 0x4d 0x41): Chunk specifies the relationship between
 *                                                 the image samples and the desired display output
 *                                                 intensity as a power function
 * -- (cHRM | 99 72 82 77 | 0x63 0x48 0x52 0x4d): Chunk used by applications that need
 *                                                device-independent specification of colors
 *                                                to specify the 1931 CIE x,y chromaticities
 *                                                of the red, green, and blue primaries used
 *                                                in the image, and the referenced white point
 * -- (sRGB | 115 82 71 66 | 0x73 0x52 0x47 0x42): Chunk indicates that the image samples conform
 *                                                 to the sRGB color space,and should be displayed
 *                                                 using the specified rendering intent as defined
 *                                                 by the International Color Consortium
 * -- (iCCP | 105 67 67 80 | 0x69 0x43 0x43 0x50): Chunk indicates that the image samples conform
 *                                                 to the color space represented by the embedded
 *                                                 ICC profile as defined by the
 *                                                 International Color Consortium
 * -- (sBIT | 115 66 73 84 | 0x73 0x42 0x49 0x54): Chunk is provided in order to store the original
 *                                                 number of significant bits
 * - Textual information:
 * -- (tEXt | 116 69 88 116 | 0x74 0x45 0x58 0x74): Chunk contains stored textual information that
 *                                                  the encoder wishes to record with the image
 * -- (zTXt | 122 84 88 116 | 0x7a 0x54 0x58 0x74): Chunk contains textual data, just as tEXt does,
 *                                                  but zTXt takes advantage of compression
 * -- (iTXt | 105 84 88 116 | 0x69 0x54 0x58 0x74): Chunk is semantically equivalent
 *                                                  to the tEXt and zTXt chunks, but the textual
 *                                                  data is in the UTF-8 encoding
 *                                                  of the Unicode character set instead of Latin-1
 * - Miscellaneous information:
 * -- (bKGD | 98 75 71 68 | 0x62 0x4b 0x47 0x44): Chunk specifies a default background color
 *                                                to present the image against
 *                                                (viewers are not bound to honor this chunk;
 *                                                a viewer can choose to use
 *                                                a different background)
 * -- (pHYs | 112 72 89 115 | 0x70 0x48 0x59 0x73): Chunk specifies the intended pixel size
 *                                                  or aspect ratio for display of the image
 * -- (sPLT | 115 80 76 84 | 0x73 0x50 0x4c 0x54): Chunk can be used to suggest a reduced palette
 *                                                 to be used when the display device is not
 *                                                 capable of displaying the full range of colors
 *                                                 present in the image
 * -- (hIST | 104 73 83 84 | 0x68 0x49 0x53 0x54): Chunk gives the approximate usage frequency
 *                                                 of each color in the color palette
 * - Time stamp information:
 * -- (tIME | 116 73 77 69 | 0x74 0x49 0x4d 0x45): Chunk gives the time
 *                                                 of the last image modification
 */
typedef enum {
    PNG_CHUNK_TYPE_IDAT = UINT32_C(0x49444154),
    PNG_CHUNK_TYPE_IEND = UINT32_C(0x49454e44),
    PNG_CHUNK_TYPE_IHDR = UINT32_C(0x49484452),
    PNG_CHUNK_TYPE_PLTE = UINT32_C(0x504c5445),
    PNG_CHUNK_TYPE_TRNS = UINT32_C(0x74524e53),
    PNG_CHUNK_TYPE_BKGD = UINT32_C(0x624b4744),
    PNG_CHUNK_TYPE_TEXT = UINT32_C(0x74455874),
    PNG_CHUNK_TYPE_ZTXT = UINT32_C(0x7a545874),
    PNG_CHUNK_TYPE_ITXT = UINT32_C(0x69545874),
    PNG_CHUNK_TYPE_TIME = UINT32_C(0x74494d45),
    PNG_CHUNK_TYPE_PHYS = UINT32_C(0x70485973),
    PNG_CHUNK_TYPE_GAMA = UINT32_C(0x67414d41),
    PNG_CHUNK_TYPE_CHRM = UINT32_C(0x6348524d),
    PNG_CHUNK_TYPE_SRGB = UINT32_C(0x73524742),
    PNG_CHUNK_TYPE_ICCP = UINT32_C(0x69434350),
    PNG_CHUNK_TYPE_SBIT = UINT32_C(0x73424954),
    PNG_CHUNK_TYPE_SPLT = UINT32_C(0x73504c54),
    PNG_CHUNK_TYPE_HIST = UINT32_C(0x68495354),
    PNG_CHUNK_TYPE_UNKNOWN = UINT32_C(0xFFFFFFFF), /* Warning! Custom value */
} png_chunk_type_t;

typedef enum {
    PNG_COLOR_NUM_CHANNEL_GREY = UINT8_C(1),
    PNG_COLOR_NUM_CHANNEL_RGB = UINT8_C(3),
    PNG_COLOR_NUM_CHANNEL_PALETTE = UINT8_C(1),
    PNG_COLOR_NUM_CHANNEL_GREYA = UINT8_C(2),
    PNG_COLOR_NUM_CHANNEL_RGBA = UINT8_C(4),
    PNG_COLOR_NUM_CHANNEL_BAD = 0, /* Warning! Custom value */
} png_color_num_channel_t;

typedef enum {
    PNG_COLOR_GREY_DEPTH_1 = 1,
    PNG_COLOR_GREY_DEPTH_2 = 2,
    PNG_COLOR_GREY_DEPTH_4 = 4,
    PNG_COLOR_GREY_DEPTH_8 = 8,
    PNG_COLOR_GREY_DEPTH_16 = 16,
    PNG_COLOR_RGB_DEPTH_8 = 8,
    PNG_COLOR_RGB_DEPTH_16 = 16,
    PNG_COLOR_PALETTE_DEPTH_1 = 1,
    PNG_COLOR_PALETTE_DEPTH_2 = 2,
    PNG_COLOR_PALETTE_DEPTH_4 = 4,
    PNG_COLOR_PALETTE_DEPTH_8 = 8,
    PNG_COLOR_GREYA_DEPTH_8 = 8,
    PNG_COLOR_GREYA_DEPTH_16 = 16,
    PNG_COLOR_RGBA_DEPTH_8 = 8,
    PNG_COLOR_RGBA_DEPTH_16 = 16,
} png_color_depth_t;

typedef enum {
    CRITICAL_CHUNK_IHDR_ARRAY_INDEX = 0,
    CRITICAL_CHUNK_IDAT_ARRAY_INDEX,
    CRITICAL_CHUNK_PLTE_ARRAY_INDEX,
    CRITICAL_CHUNK_IEND_ARRAY_INDEX,
    CRITICAL_CHUNK_ARRAY_SIZE,
} chunk_critical_array_t;

/*************************************************************************************************/

static inline png_check_res_t png_pic_buffer_check(const uint8_t *buffer, size_t buffer_size);
static png_check_res_t png_header_check(const uint8_t *buffer,
                                        size_t buffer_size,
                                        ihdr_chunk_struct_t *ihdr_data);
static png_check_res_t png_chunk_check(const uint8_t *buffer,
                                       size_t buffer_size,
                                       ihdr_chunk_struct_t *ihdr_data);
static png_color_num_channel_t get_number_color_channels(uint8_t color);
static png_check_res_t png_pic_size_check(uint32_t width,
                                          uint32_t height,
                                          uint8_t color,
                                          uint8_t depth);
static png_check_res_t png_color_check(uint8_t color, uint8_t depth);
static png_check_res_t png_calculate_crc32(const uint8_t *data, size_t data_size);
static png_chunk_type_t png_get_chunk_type(const uint8_t *chunk_name_ptr);

/*************************************************************************************************/

/* Acc. to 5.5 Cyclic Redundancy Code algorithm:
 * chunk CRCs are calculated using standard CRC methods with pre and post conditioning,
 * as defined by ISO 3309 [ISO-3309] or ITU-T V.42 [ITU-T-V42]. The CRC polynomial employed is
 * x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x+1
 * The 32-bit CRC register is initialized to all 1's, and then the data from each byte is processed
 * from the least significant bit (1) to the most significant bit (128).
 * After all the data bytes are processed, the CRC register is inverted
 * (its ones complement is taken). This value is transmitted (stored in the file) MSB first.
 * For the purpose of separating into bytes and ordering,
 * the least significant bit of the 32-bit CRC is defined to be the coefficient of the x31 term.
 * Practical calculation of the CRC always employs a precalculated table to greatly accelerate
 * the computation.
 * A 4-byte CRC (Cyclic Redundancy Check) calculated on the preceding bytes in the chunk,
 * including the chunk type code and chunk data fields, but not including the length field.
 * The CRC is always present, even for chunks containing no data. */
static uint32_t png_calculate_crc32(const uint8_t *data, size_t data_size)
{
    /* Pre-calculated data (used 0xEDB88320L polynomial) */
    uint32_t crc32_table[256] = {
                0, 1996959894, 3993919788, 2567524794,
        124634137, 1886057615, 3915621685, 2657392035,
        249268274, 2044508324, 3772115230, 2547177864,
        162941995, 2125561021, 3887607047, 2428444049,
        498536548, 1789927666, 4089016648, 2227061214,
        450548861, 1843258603, 4107580753, 2211677639,
        325883990, 1684777152, 4251122042, 2321926636,
        335633487, 1661365465, 4195302755, 2366115317,
        997073096, 1281953886, 3579855332, 2724688242,
        1006888145, 1258607687, 3524101629, 2768942443,
        901097722, 1119000684, 3686517206, 2898065728,
        853044451, 1172266101, 3705015759, 2882616665,
        651767980, 1373503546, 3369554304, 3218104598,
        565507253, 1454621731, 3485111705, 3099436303,
        671266974, 1594198024, 3322730930, 2970347812,
        795835527, 1483230225, 3244367275, 3060149565,
        1994146192, 31158534, 2563907772, 4023717930,
        1907459465, 112637215, 2680153253, 3904427059,
        2013776290, 251722036, 2517215374, 3775830040,
        2137656763, 141376813, 2439277719, 3865271297,
        1802195444, 476864866, 2238001368, 4066508878,
        1812370925, 453092731, 2181625025, 4111451223,
        1706088902, 314042704, 2344532202, 4240017532,
        1658658271, 366619977, 2362670323, 4224994405,
        1303535960, 984961486, 2747007092, 3569037538,
        1256170817, 1037604311, 2765210733, 3554079995,
        1131014506, 879679996, 2909243462, 3663771856,
        1141124467, 855842277, 2852801631, 3708648649,
        1342533948, 654459306, 3188396048, 3373015174,
        1466479909, 544179635, 3110523913, 3462522015,
        1591671054, 702138776, 2966460450, 3352799412,
        1504918807, 783551873, 3082640443, 3233442989,
        3988292384, 2596254646, 62317068, 1957810842,
        3939845945, 2647816111, 81470997, 1943803523,
        3814918930, 2489596804, 225274430, 2053790376,
        3826175755, 2466906013, 167816743, 2097651377,
        4027552580, 2265490386, 503444072, 1762050814,
        4150417245, 2154129355, 426522225, 1852507879,
        4275313526, 2312317920, 282753626, 1742555852,
        4189708143, 2394877945, 397917763, 1622183637,
        3604390888, 2714866558, 953729732, 1340076626,
        3518719985, 2797360999, 1068828381, 1219638859,
        3624741850, 2936675148, 906185462, 1090812512,
        3747672003, 2825379669, 829329135, 1181335161,
        3412177804, 3160834842, 628085408, 1382605366,
        3423369109, 3138078467, 570562233, 1426400815,
        3317316542, 2998733608, 733239954, 1555261956,
        3268935591, 3050360625, 752459403, 1541320221,
        2607071920, 3965973030, 1969922972, 40735498,
        2617837225, 3943577151, 1913087877, 83908371,
        2512341634, 3803740692, 2075208622, 213261112,
        2463272603, 3855990285, 2094854071, 198958881,
        2262029012, 4057260610, 1759359992, 534414190,
        2176718541, 4139329115, 1873836001, 414664567,
        2282248934, 4279200368, 1711684554, 285281116,
        2405801727, 4167216745, 1634467795, 376229701,
        2685067896, 3608007406, 1308918612, 956543938,
        2808555105, 3495958263, 1231636301, 1047427035,
        2932959818, 3654703836, 1088359270, 936918000,
        2847714899, 3736837829, 1202900863, 817233897,
        3183342108, 3401237130, 1404277552, 615818150,
        3134207493, 3453421203, 1423857449, 601450431,
        3009837614, 3294710456, 1567103746, 711928724,
        3020668471, 3272380065, 1510334235, 755167117
    };
    uint32_t r = 0xFFFFFFFF;

    for (size_t i = 0; i < data_size; ++i) {
        r = crc32_table[(r ^ data[i]) & 0xFF] ^ (r >> 8);
    }
    r ^= 0xFFFFFFFF;

    return r;
}

static png_chunk_type_t png_get_chunk_type(const uint8_t *chunk_name_ptr)
{
    png_chunk_type_t chunk_type = (png_chunk_type_t) (be32toh(GET_32BIT_VALUE(chunk_name_ptr)));

    switch (chunk_type) {
    case PNG_CHUNK_TYPE_IDAT:
    case PNG_CHUNK_TYPE_IEND:
    case PNG_CHUNK_TYPE_IHDR:
    case PNG_CHUNK_TYPE_PLTE:
    case PNG_CHUNK_TYPE_TRNS:
    case PNG_CHUNK_TYPE_BKGD:
    case PNG_CHUNK_TYPE_TEXT:
    case PNG_CHUNK_TYPE_ZTXT:
    case PNG_CHUNK_TYPE_ITXT:
    case PNG_CHUNK_TYPE_TIME:
    case PNG_CHUNK_TYPE_PHYS:
    case PNG_CHUNK_TYPE_GAMA:
    case PNG_CHUNK_TYPE_CHRM:
    case PNG_CHUNK_TYPE_SRGB:
    case PNG_CHUNK_TYPE_ICCP:
    case PNG_CHUNK_TYPE_SBIT:
    case PNG_CHUNK_TYPE_SPLT:
    case PNG_CHUNK_TYPE_HIST:
        return chunk_type;
    default:
        return PNG_CHUNK_TYPE_UNKNOWN;
    }

    return PNG_CHUNK_TYPE_UNKNOWN;
}

static png_color_num_channel_t get_number_color_channels(uint8_t color)
{
    switch ((png_color_t) color) {
    case PNG_COLOR_GREY:
        return PNG_COLOR_NUM_CHANNEL_GREY;
    case PNG_COLOR_RGB:
        return PNG_COLOR_NUM_CHANNEL_RGB;
    case PNG_COLOR_PALETTE:
        return PNG_COLOR_NUM_CHANNEL_PALETTE;
    case PNG_COLOR_GREYA:
        return PNG_COLOR_NUM_CHANNEL_GREYA;
    case PNG_COLOR_RGBA:
        return PNG_COLOR_NUM_CHANNEL_RGBA;
    default:
        return PNG_COLOR_NUM_CHANNEL_BAD;
    }

    return PNG_COLOR_NUM_CHANNEL_BAD;
}

static png_check_res_t png_pic_size_check(uint32_t width,
                                          uint32_t height,
                                          uint8_t color,
                                          uint8_t depth)
{
    uint32_t width_height = 0;
    uint32_t channel_depth = 0;
    uint32_t bit_color = BYTES_PER_CHANNEL_COLOR;
    uint32_t width_height_channel_depth = 0;
    uint32_t num_color_channel = 0;
    uint32_t padding = PNG_INTERLACE_FILTER_PADDING_SIZE;
    uint32_t max_decode_buffer_bit_size = 0;
    uint32_t max_decode_buffer_byte_size = 0;

    if (width > INT_MAX || height > INT_MAX) {
        return PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW;
    }

    if (width == 0 || height == 0) {
        return PNG_CHECKER_RES_ERROR_BAD_PIC_SIZES;
    }

    num_color_channel = (uint32_t) get_number_color_channels(color);
    if (num_color_channel == PNG_COLOR_NUM_CHANNEL_BAD) {
        return PNG_CHECKER_RES_ERROR_BAD_STATE;
    }

    if (__builtin_mul_overflow(width, height, &width_height)) {
        return PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW;
    }
    if (__builtin_mul_overflow(num_color_channel, depth, &channel_depth)) {
        return PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW;
    }
    if (__builtin_mul_overflow(width_height, channel_depth, &width_height_channel_depth)) {
        return PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW;
    }

    if (__builtin_add_overflow(width_height_depth_channel, padding, &max_decode_buffer_bit_size)) {
        return PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW;
    }
    if (max_decode_buffer_bit_size == 0 || max_decode_buffer_bit_size > INT_MAX) {
        return PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW;
    }

    max_decode_buffer_byte_size = max_decode_buffer_bit_size / bit_color;
    if (max_decode_buffer_byte_size == 0 || max_decode_buffer_byte_size > INT_MAX) {
        return PNG_CHECKER_RES_ERROR_PIC_SIZE_OVERFLOW;
    }

    return PNG_CHECKER_RES_SUCCESS;
}

static png_check_res_t png_color_check(uint8_t color, uint8_t depth)
{
    png_color_t cur_color = (png_color_t) color;
    png_color_depth_t cur_depth = (png_color_depth_t) depth;

    switch (cur_color) {
    case PNG_COLOR_GREY: {
        if (cur_depth == PNG_COLOR_GREY_DEPTH_1
         || cur_depth == PNG_COLOR_GREY_DEPTH_2
         || cur_depth == PNG_COLOR_GREY_DEPTH_4
         || cur_depth == PNG_COLOR_GREY_DEPTH_8
         || cur_depth == PNG_COLOR_GREY_DEPTH_16) {
            return PNG_CHECKER_RES_SUCCESS;
        }
        break;
    }
    case PNG_COLOR_RGB: {
        if (cur_depth == PNG_COLOR_RGB_DEPTH_8 || cur_depth == PNG_COLOR_RGB_DEPTH_16) {
            return PNG_CHECKER_RES_SUCCESS;
        }
        break;
    }
    case PNG_COLOR_PALETTE: {
        if (cur_depth == PNG_COLOR_PALETTE_DEPTH_1
         || cur_depth == PNG_COLOR_PALETTE_DEPTH_2
         || cur_depth == PNG_COLOR_PALETTE_DEPTH_4
         || cur_depth == PNG_COLOR_PALETTE_DEPTH_8) {
            return PNG_CHECKER_RES_SUCCESS;
        }
        break;
    }
    case PNG_COLOR_GREYA: {
        if (cur_depth == PNG_COLOR_GREYA_DEPTH_8 || cur_depth == PNG_COLOR_GREYA_DEPTH_16) {
            return PNG_CHECKER_RES_SUCCESS;
        }
        break;
    }
    case PNG_COLOR_RGBA: {
        if (cur_depth == PNG_COLOR_RGBA_DEPTH_8 || cur_depth == PNG_COLOR_RGBA_DEPTH_16) {
            return PNG_CHECKER_RES_SUCCESS;
        }
        break;
    }
    default:
        return PNG_CHECKER_RES_ERROR_BAD_COLOR;
    }

    return PNG_CHECKER_RES_ERROR_BAD_COLOR;
}

static inline png_check_res_t png_pic_buffer_check(const uint8_t *buffer, size_t buffer_size)
{
    size_t buffer_end = 0;

    if (buffer == NULL) {
        return PNG_CHECKER_RES_ERROR_BAD_PARAMETERS;
    }

    if (buffer_size <= PNG_FULL_HEADER_SIZE || buffer_size > INT_MAX) {
        return PNG_CHECKER_RES_ERROR_WRONG_SIZE;
    }

    if (buffer_size < MIN_PNG_FILE_SIZE) {
        return PNG_CHECKER_RES_ERROR_WRONG_SIZE;
    }

    if (__builtin_add_overflow((size_t) buffer, buffer_size, &buffer_end)) {
        return PNG_CHECKER_RES_ERROR_WRONG_SIZE;
    }

    return PNG_CHECKER_RES_SUCCESS;
}

static png_check_res_t png_header_check(const uint8_t *buffer,
                                        size_t buffer_size,
                                        ihdr_chunk_struct_t *ihdr_data)
{
    uint32_t width = 0;
    uint32_t height = 0;
    uint8_t bit_depth = 0;
    uint8_t color_type = 0;
    uint8_t compression_method = 0;
    uint8_t filter_method = 0;
    uint8_t interlace_method = 0;
    png_check_res_t res = PNG_CHECKER_RES_ERROR_GENERIC;
    uint32_t stored_crc32 = 0;
    uint32_t calculated_crc32 = 0;
    const uint8_t *ihdr_ptr = NULL;
    png_chunk_type_t ihdr_type = PNG_CHUNK_TYPE_UNKNOWN;
    uint32_t ihdr_data_size = 0;

    (void) buffer_size;

    if (memcmp(PNG_HEADER_SIGNATURE_PTR(buffer),
               png_header_signature,
               ARRAY_SIZE(png_header_signature)) != 0) {
        return PNG_CHECKER_RES_ERROR_BAD_SIGNATURE;
    }

    ihdr_ptr = PNG_IHDR_PTR(buffer);

    ihdr_data_size = be32toh(GET_32BIT_VALUE(ihdr_ptr));
    if (ihdr_data_size != PNG_IHDR_DATA_SIZE) {
        return PNG_CHECKER_RES_ERROR_BAD_IHDR_SIZE;
    }

    ihdr_type = png_get_chunk_type(PNG_CHUNK_TYPE_PTR(ihdr_ptr));
    if (ihdr_type == PNG_CHUNK_TYPE_UNKNOWN) {
        return PNG_CHECKER_RES_ERROR_CHUNK_UNKNOWN_TYPE;
    }
    printf("\t chunk_type = 0x%x\n", ihdr_type);
    if (ihdr_type != PNG_CHUNK_TYPE_IHDR) {
        return PNG_CHECKER_RES_ERROR_BAD_CHUNK_TYPE;
    }

    bit_depth = *(uint8_t *) PNG_IHDR_BIT_DEPTH_PTR(ihdr_ptr);
    color_type = *(uint8_t *) PNG_IHDR_COLOR_TYPE_PTR(ihdr_ptr);
    res = png_color_check(color_type, bit_depth);
    if (res != PNG_CHECKER_RES_SUCCESS) {
        return res;
    }
    printf("\t bit_depth = %u\n", bit_depth);
    printf("\t color_type = %u\n", color_type);

    width = be32toh(GET_32BIT_VALUE(PNG_IHDR_PIC_WIDTH_PTR(ihdr_ptr)));
    height = be32toh(GET_32BIT_VALUE(PNG_IHDR_PIC_HEIGHT_PTR(ihdr_ptr)));
    res = png_pic_size_check(width, height, color_type, bit_depth);
    if (res != PNG_CHECKER_RES_SUCCESS) {
        return res;
    }
    printf("\t width = %u\n", width);
    printf("\t height = %u\n", height);

    compression_method = *(uint8_t *) PNG_IHDR_COMPRESSION_METHOD_PTR(ihdr_ptr);
    if (compression_method != BASIC_COMPRESSION_METHOD) {
        return PNG_CHECKER_RES_ERROR_BAD_COMP_METH;
    }
    printf("\t compression_method = %u\n", compression_method);

    filter_method = *(uint8_t *) PNG_IHDR_FILTER_METHOD_PTR(ihdr_ptr);
    if (filter_method != BASIC_FILTER_METHOD) {
        return PNG_CHECKER_RES_ERROR_BAD_FILT_METH;
    }
    printf("\t filter_method = %u\n", filter_method);

    interlace_method = *(uint8_t *) PNG_IHDR_INTERLACE_METHOD_PTR(ihdr_ptr);
    if (interlace_method > MAX_INTERLACE_METHOD) {
        return PNG_CHECKER_RES_ERROR_BAD_INT_METH;
    }
    printf("\t interlace_method = %u\n", interlace_method);

    stored_crc32 = be32toh(GET_32BIT_VALUE(PNG_CRC32_VALUE_PTR(ihdr_ptr, ihdr_data_size)));
    calculated_crc32 = png_calculate_crc32(PNG_CHUNK_TYPE_PTR(ihdr_ptr),
                                           ihdr_data_size + PNG_CHUNK_TAG_TYPE_SIZE);
    if (stored_crc32 != calculated_crc32) {
        return PNG_CHECKER_RES_ERROR_BAD_CRC32;
    }
    printf("\t stored_crc32 = %u\n", stored_crc32);

    ihdr_data->bit_depth = bit_depth;
    ihdr_data->color_type = color_type;
    ihdr_data->compression_method = compression_method;
    ihdr_data->filter_method = filter_method;
    ihdr_data->interlace_method = interlace_method;
    ihdr_data->height = height;
    ihdr_data->width = width;

    return PNG_CHECKER_RES_SUCCESS;
}

static png_check_res_t png_chunk_check(const uint8_t *buffer,
                                       size_t buffer_size,
                                       ihdr_chunk_struct_t *ihdr_data)
{
    const uint8_t *chunk_ptr = NULL;
    uint32_t chunk_data_size = 0;
    png_chunk_type_t chunk_type = PNG_CHUNK_TYPE_UNKNOWN;
    size_t min_chunks_size = 0;
    size_t full_chunks_size = 0;
    uint32_t stored_crc32 = 0;
    uint32_t calculated_crc32 = 0;
    bool critical_chunk[CRITICAL_CHUNK_ARRAY_SIZE] = {
        [CRITICAL_CHUNK_IHDR_ARRAY_INDEX] = true,
        [CRITICAL_CHUNK_IDAT_ARRAY_INDEX] = false,
        [CRITICAL_CHUNK_PLTE_ARRAY_INDEX] = false,
        [CRITICAL_CHUNK_IEND_ARRAY_INDEX] = false,
    };
    bool is_all_needed_critical_chunks = false;
    uint32_t palette_size = 0;

    for (chunk_ptr = PNG_FIRST_CHUNK_PTR(buffer); ;chunk_ptr = buffer + full_chunks_size) {
        printf("\n");
        if (__builtin_add_overflow(PNG_BUFFER_STEP_DISTANCE(buffer, chunk_ptr),
                                   PNG_MIN_CHUNK_SIZE,
                                   &min_chunks_size)) {
            return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
        }
        if (min_chunks_size > buffer_size) {
            return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
        }

        chunk_data_size = be32toh(GET_32BIT_VALUE(chunk_ptr));
        if (chunk_data_size > INT_MAX) {
            return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
        }
        printf("\t chunk_data_size = %u\n", chunk_data_size);
        if (__builtin_add_overflow(min_chunks_size, chunk_data_size, &full_chunks_size)) {
            return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
        }
        if (full_chunks_size > buffer_size) {
            return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
        }

        chunk_type = png_get_chunk_type(PNG_CHUNK_TYPE_PTR(chunk_ptr));
        printf("\t chunk_type = 0x%x\n", chunk_type);
        switch (chunk_type) {
        case PNG_CHUNK_TYPE_IDAT:
            /** @TODO: >= 16 ? */
            critical_chunk[CRITICAL_CHUNK_IDAT_ARRAY_INDEX] = true;
            break;

        case PNG_CHUNK_TYPE_IEND:
            if (critical_chunk[CRITICAL_CHUNK_IEND_ARRAY_INDEX]) {
                return PNG_CHECKER_RES_ERROR_BAD_IEND_CHUNK_TYPE;
            }
            if (chunk_data_size != 0 || full_chunks_size != buffer_size) {
                return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
            }
            critical_chunk[CRITICAL_CHUNK_IEND_ARRAY_INDEX] = true;
            break;

        case PNG_CHUNK_TYPE_IHDR:
            if (critical_chunk[CRITICAL_CHUNK_IHDR_ARRAY_INDEX]) {
                return PNG_CHECKER_RES_ERROR_BAD_IHDR_CHUNK_TYPE;
            }
            if (chunk_data_size != PNG_IHDR_DATA_SIZE) {
                return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
            }
            critical_chunk[CRITICAL_CHUNK_IHDR_ARRAY_INDEX] = true;
            break;

        case PNG_CHUNK_TYPE_PLTE:
            if (critical_chunk[CRITICAL_CHUNK_PLTE_ARRAY_INDEX]) {
                return PNG_CHECKER_RES_ERROR_BAD_PLTE_CHUNK_TYPE;
            }
            /*  it shall not appear for colour types 0 and 4 */
            if (ihdr_data->color_type == PNG_COLOR_GREY
             || ihdr_data->color_type == PNG_COLOR_GREYA) {
                return PNG_CHECKER_RES_ERROR_BAD_CHUNK_TYPE;
            }
            if ((chunk_data_size % PNG_CHUNK_PLTE_DIV_DATA_SIZE) != 0) {
                return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
            }
            palette_size = chunk_data_size / PNG_CHUNK_PLTE_DIV_DATA_SIZE;
            if (palette_size == 0 || palette_size > PNG_CHUNK_PLTE_MAX_COLOR_SET) {
                return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
            }
            critical_chunk[CRITICAL_CHUNK_PLTE_ARRAY_INDEX] = true;
            break;

        case PNG_CHUNK_TYPE_TRNS:
            if (ihdr_data->color_type == PNG_COLOR_PALETTE) {
                if (chunk_data_size > palette_size) {
                    return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
                }
            }
            if (ihdr_data->color_type == PNG_COLOR_GREY) {
                if (chunk_data_size != PNG_CHUNK_TRNS_GREY_DATA_SIZE) {
                    return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
                }
            }
            if (ihdr_data->color_type == PNG_COLOR_RGB) {
                if (chunk_data_size != PNG_CHUNK_TRNS_RGB_DATA_SIZE) {
                    return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
                }
            }
            /* shall not appear for colour types 4 and 6 */
            if (ihdr_data->color_type == PNG_COLOR_GREYA
             || ihdr_data->color_type == PNG_COLOR_RGBA) {
                return PNG_CHECKER_RES_ERROR_BAD_CHUNK_TYPE;
            }
            break;

        case PNG_CHUNK_TYPE_BKGD:
            if (ihdr_data->color_type == PNG_COLOR_GREY
             || ihdr_data->color_type == PNG_COLOR_GREYA) {
                if (chunk_data_size != PNG_CHUNK_BKGD_GREY_GREYA_DATA_SIZE) {
                    return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
                }
            }
            if (ihdr_data->color_type == PNG_COLOR_RGB
             || ihdr_data->color_type == PNG_COLOR_RGBA) {
                if (chunk_data_size != PNG_CHUNK_BKGD_RGB_RGBA_DATA_SIZE) {
                    return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
                }
            }
            if (ihdr_data->color_type == PNG_COLOR_PALETTE) {
                if (chunk_data_size != PNG_CHUNK_BKGD_PALETTE_DATA_SIZE) {
                    return PNG_CHECKER_RES_ERROR_BAD_CHUNK_SIZE;
                }
            }
            break;

        case PNG_CHUNK_TYPE_TEXT:
            break;

        case PNG_CHUNK_TYPE_ZTXT:
            break;

        case PNG_CHUNK_TYPE_ITXT:
            break;

        case PNG_CHUNK_TYPE_TIME:
            break;

        case PNG_CHUNK_TYPE_PHYS:
            break;

        case PNG_CHUNK_TYPE_GAMA:
            break;

        case PNG_CHUNK_TYPE_CHRM:
            break;

        case PNG_CHUNK_TYPE_SRGB:
            break;

        case PNG_CHUNK_TYPE_ICCP:
            break;

        case PNG_CHUNK_TYPE_SBIT:
            break;

        case PNG_CHUNK_TYPE_SPLT:
            break;

        case PNG_CHUNK_TYPE_HIST:
            break;

        case PNG_CHUNK_TYPE_UNKNOWN:

        default:
            return PNG_CHECKER_RES_ERROR_CHUNK_UNKNOWN_TYPE;
        }

        stored_crc32 = be32toh(GET_32BIT_VALUE(PNG_CRC32_VALUE_PTR(chunk_ptr, chunk_data_size)));
        calculated_crc32 = png_calculate_crc32(PNG_CHUNK_TYPE_PTR(chunk_ptr),
                                               chunk_data_size + PNG_CHUNK_TAG_TYPE_SIZE);
        if (stored_crc32 != calculated_crc32) {
            return PNG_CHECKER_RES_ERROR_BAD_CRC32;
        }
        printf("\t stored_crc32 = %u\n", stored_crc32);

        if (full_chunks_size == buffer_size) {
            if (chunk_type != PNG_CHUNK_TYPE_IEND) {
                return PNG_CHECKER_RES_ERROR_BAD_FORMAT;
            }
            break;
        }
    }

    is_all_needed_critical_chunks = critical_chunk[CRITICAL_CHUNK_IHDR_ARRAY_INDEX]
                                 && critical_chunk[CRITICAL_CHUNK_IDAT_ARRAY_INDEX]
                                 && critical_chunk[CRITICAL_CHUNK_IEND_ARRAY_INDEX];
    if (!is_all_needed_critical_chunks) {
        return PNG_CHECKER_RES_ERROR_BAD_FORMAT;
    }
    if (ihdr_data->color_type == PNG_COLOR_PALETTE
     && !critical_chunk[CRITICAL_CHUNK_PLTE_ARRAY_INDEX]) {
        return PNG_CHECKER_RES_ERROR_BAD_FORMAT;
    }

    return PNG_CHECKER_RES_SUCCESS;
}

/*************************************************************************************************/

png_check_res_t png_check(const uint8_t *pic_buffer, size_t pic_buffer_size)
{
    png_check_res_t res = PNG_CHECKER_RES_ERROR_GENERIC;
    ihdr_chunk_struct_t ihdr_data = { };

    res = png_pic_buffer_check(pic_buffer, pic_buffer_size);
    if (res != PNG_CHECKER_RES_SUCCESS) {
        return res;
    }

    res = png_header_check(pic_buffer, pic_buffer_size, &ihdr_data);
    if (res != PNG_CHECKER_RES_SUCCESS) {
        return res;
    }

    res = png_chunk_check(pic_buffer, pic_buffer_size, &ihdr_data);
    if (res != PNG_CHECKER_RES_SUCCESS) {
        return res;
    }

    return PNG_CHECKER_RES_SUCCESS;
}

/*************************************************************************************************/
