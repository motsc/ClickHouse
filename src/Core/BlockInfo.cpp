#include <base/types.h>
#include <Common/Exception.h>
#include <IO/ReadBuffer.h>
#include <IO/WriteBuffer.h>
#include <IO/VarInt.h>
#include <IO/ReadHelpers.h>
#include <IO/WriteHelpers.h>
#include <Core/BlockInfo.h>


namespace DB
{

namespace ErrorCodes
{
    extern const int UNKNOWN_BLOCK_INFO_FIELD;
    extern const int INCORRECT_DATA;
}

/// Maximum number of entries in the out_of_order_buckets list.
/// Two-level aggregation uses at most 256 buckets; cap at 65536 for safety.
static constexpr size_t MAX_OUT_OF_ORDER_BUCKETS = 65536;


/// Write values in binary form. NOTE: You could use protobuf, but it would be overkill for this case.
void BlockInfo::write(WriteBuffer & out, UInt64 server_protocol_revision) const
{
/// Set of pairs `FIELD_NUM`, value in binary form. Then 0.
#define WRITE_FIELD(TYPE, NAME, DEFAULT, FIELD_NUM, MIN_PROTOCOL_REVISION) \
    if (server_protocol_revision >= (MIN_PROTOCOL_REVISION)) \
    { \
        writeVarUInt(FIELD_NUM, out); \
        writeBinary(NAME, out); \
    }

    APPLY_FOR_BLOCK_INFO_FIELDS(WRITE_FIELD)

#undef WRITE_FIELD
    writeVarUInt(0, out);
}

/// Read values in binary form.
void BlockInfo::read(ReadBuffer & in, UInt64 client_protocol_revision)
{
    UInt64 field_num = 0;

    while (true)
    {
        readVarUInt(field_num, in);
        if (field_num == 0)
            break;

        switch (field_num)
        {
            case 1: /// is_overflows (bool)
                readBinary(is_overflows, in);
                break;

            case 2: /// bucket_num (Int32)
                readBinary(bucket_num, in);
                break;

            case 3: /// out_of_order_buckets (std::vector<Int32>)
                if (client_protocol_revision >= DBMS_MIN_REVISION_WITH_OUT_OF_ORDER_BUCKETS_IN_AGGREGATION)
                {
                    /// Read size explicitly to cap before allocating.
                    UInt64 count = 0;
                    readVarUInt(count, in);
                    if (count > MAX_OUT_OF_ORDER_BUCKETS)
                        throw Exception(
                            ErrorCodes::INCORRECT_DATA,
                            "BlockInfo: out_of_order_buckets size {} exceeds limit {}",
                            count, MAX_OUT_OF_ORDER_BUCKETS);
                    out_of_order_buckets.resize(static_cast<size_t>(count));
                    for (size_t i = 0; i < static_cast<size_t>(count); ++i)
                        readBinary(out_of_order_buckets[i], in);
                }
                break;

            default:
                throw Exception(ErrorCodes::UNKNOWN_BLOCK_INFO_FIELD, "Unknown BlockInfo field number: {}", field_num);
        }
    }
}

}
