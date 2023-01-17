
#Define BOOL UByte

#Undef TRUE
#Undef FALSE

#define FALSE 0
#define TRUE  1



'#Undef SIZE_T
'#Define SIZE_T Integer


#Define int8_t    Byte
#Define int16_t   Short
#Define int32_t   Integer

#Define uint8_t   UByte
#Define uint16_t  UShort
#Define uint32_t  UInteger

#Define int64_t   LongInt
#Define uint64_t  ULongInt


#Define uc_engine Integer 
#Define uc_hook 	SIZE_T



#define INT8_MIN         (-127i8 - 1)
#define INT16_MIN        (-32767i16 - 1)
#define INT32_MIN        (-2147483647i32 - 1)
#define INT64_MIN        (-9223372036854775807i64 - 1)
#define INT8_MAX         127i8
#define INT16_MAX        32767i16
#define INT32_MAX        2147483647i32
#define INT64_MAX        9223372036854775807i64
#define UINT8_MAX        &hffui8
#define UINT16_MAX       &hffffui16
#define UINT32_MAX       &hffffffffui32
#define UINT64_MAX       &hffffffffffffffffui64

#define __PRI_8_LENGTH_MODIFIER__ "hh"
#define __PRI_64_LENGTH_MODIFIER__ "ll"

#define PRId8         __PRI_8_LENGTH_MODIFIER__ "d"
#define PRIi8         __PRI_8_LENGTH_MODIFIER__ "i"
#define PRIo8         __PRI_8_LENGTH_MODIFIER__ "o"
#define PRIu8         __PRI_8_LENGTH_MODIFIER__ "u"
#define PRIx8         __PRI_8_LENGTH_MODIFIER__ "x"
'#define PRIX8         __PRI_8_LENGTH_MODIFIER__ "X"

#define PRId16        "hd"
#define PRIi16        "hi"
#define PRIo16        "ho"
#define PRIu16        "hu"
#define PRIx16        "hx"
'#define PRIX16        "hX"

#define PRId32        "ld"
#define PRIi32        "li"
#define PRIo32        "lo"
#define PRIu32        "lu"
#define PRIx32        "lx"
'#define PRIX32        "lX"

'#define strtoull _strtoui64

#define PRId64        __PRI_64_LENGTH_MODIFIER__ "d"
#define PRIi64        __PRI_64_LENGTH_MODIFIER__ "i"
#define PRIo64        __PRI_64_LENGTH_MODIFIER__ "o"
#define PRIu64        __PRI_64_LENGTH_MODIFIER__ "u"
#define PRIx64        __PRI_64_LENGTH_MODIFIER__ "x"
'#define PRIX64        __PRI_64_LENGTH_MODIFIER__ "X"

'#define PRId64         "d"
'#define PRIi64         "i"
'#define PRIo64         "o"
'#define PRIu64         "u"
'#define PRIx64         "x"


' misc support
' typedef signed __int64    sSIZE_T;

' #define va_copy(d,s) ((d) = (s))
' #define strcasecmp	_stricmp
' #define snprintf	_snprintf
' #define strtoll		_strtoi64

