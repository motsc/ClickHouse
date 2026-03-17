#include <base/types.h>

#include <IO/ReadBufferFromMemory.h>

#include <DataTypes/IDataType.h>
#include <DataTypes/DataTypesNumber.h>
#include <DataTypes/DataTypeString.h>
#include <DataTypes/DataTypeNullable.h>
#include <DataTypes/DataTypeArray.h>
#include <DataTypes/DataTypeMap.h>
#include <DataTypes/DataTypeTuple.h>
#include <DataTypes/DataTypeLowCardinality.h>
#include <DataTypes/DataTypeVariant.h>

#include <Columns/IColumn.h>

#include <Common/MemoryTracker.h>
#include <Common/CurrentThread.h>

#include <Interpreters/Context.h>

#include <AggregateFunctions/registerAggregateFunctions.h>

using namespace DB;

ContextMutablePtr context;
extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    if (context)
        return true;

    static SharedContextHolder shared_context = Context::createShared();
    context = Context::createGlobal(shared_context.get());
    context->makeGlobalContext();

    MainThreadStatus::getInstance();

    /// Variant type can hold AggregateFunction values, so register them.
    registerAggregateFunctions();

    return 0;
}

/// Auxiliary header at the start of the fuzz input:
///   [0]    schema_selector: chooses which deeply-nested type to deserialize
///   [1]    flags: bit 0 = native_format, bit 1 = use_specialized_prefixes
///   [2..9] rows: uint64_t LE, capped at 65536
///
/// Schemas (chosen by schema_selector % 8):
///   0: Array(Array(UInt32))                                          — nested array offsets
///   1: Map(String, Nullable(Float64))                                — nullable map values
///   2: Tuple(LowCardinality(String), Array(Int8))                   — mixed LC and array
///   3: Array(Variant(UInt32, String, Nullable(Float64)))             — Variant inside Array
///   4: LowCardinality(Nullable(String))                              — nullable LC
///   5: Array(Map(String, UInt64))                                    — array of maps
///   6: Tuple(Nullable(UInt32), Array(String), LowCardinality(String)) — complex tuple
///   7: Map(LowCardinality(String), Array(UInt8))                    — LC keys with array values
///
/// The schema is fixed per invocation (selected from aux header), so libFuzzer only
/// needs to evolve the serialized data, not rediscover the schema encoding.
struct AuxiliaryRandomData
{
    uint8_t schema_selector;
    uint8_t flags;
    uint64_t rows;
};

static DataTypePtr makeNestedType(uint8_t selector)
{
    switch (selector % 8)
    {
        case 0:
            return std::make_shared<DataTypeArray>(
                std::make_shared<DataTypeArray>(std::make_shared<DataTypeUInt32>()));
        case 1:
            return std::make_shared<DataTypeMap>(
                std::make_shared<DataTypeString>(),
                std::make_shared<DataTypeNullable>(std::make_shared<DataTypeFloat64>()));
        case 2:
            return std::make_shared<DataTypeTuple>(DataTypes{
                std::make_shared<DataTypeLowCardinality>(std::make_shared<DataTypeString>()),
                std::make_shared<DataTypeArray>(std::make_shared<DataTypeInt8>()),
            });
        case 3:
            return std::make_shared<DataTypeArray>(
                std::make_shared<DataTypeVariant>(DataTypes{
                    std::make_shared<DataTypeUInt32>(),
                    std::make_shared<DataTypeString>(),
                    std::make_shared<DataTypeNullable>(std::make_shared<DataTypeFloat64>()),
                }));
        case 4:
            return std::make_shared<DataTypeLowCardinality>(
                std::make_shared<DataTypeNullable>(std::make_shared<DataTypeString>()));
        case 5:
            return std::make_shared<DataTypeArray>(
                std::make_shared<DataTypeMap>(
                    std::make_shared<DataTypeString>(),
                    std::make_shared<DataTypeUInt64>()));
        case 6:
            return std::make_shared<DataTypeTuple>(DataTypes{
                std::make_shared<DataTypeNullable>(std::make_shared<DataTypeUInt32>()),
                std::make_shared<DataTypeArray>(std::make_shared<DataTypeString>()),
                std::make_shared<DataTypeLowCardinality>(std::make_shared<DataTypeString>()),
            });
        case 7:
        default:
            return std::make_shared<DataTypeMap>(
                std::make_shared<DataTypeLowCardinality>(std::make_shared<DataTypeString>()),
                std::make_shared<DataTypeArray>(std::make_shared<DataTypeUInt8>()));
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    try
    {
        total_memory_tracker.resetCounters();
        total_memory_tracker.setHardLimit(1_GiB);
        CurrentThread::get().memory_tracker.resetCounters();
        CurrentThread::get().memory_tracker.setHardLimit(1_GiB);

        if (size < sizeof(AuxiliaryRandomData))
            return 0;

        const auto * aux = reinterpret_cast<const AuxiliaryRandomData *>(data);
        const size_t rows = static_cast<size_t>(aux->rows % 65536);
        const bool use_native_format = (aux->flags & 1) != 0;
        const bool use_specialized_prefixes = (aux->flags & 2) != 0;

        DataTypePtr type = makeNestedType(aux->schema_selector);
        auto serialization = type->getDefaultSerialization();

        size -= sizeof(AuxiliaryRandomData);
        data += sizeof(AuxiliaryRandomData);

        DB::ReadBufferFromMemory in(data, size);

        FormatSettings format_settings;
        format_settings.binary.max_binary_array_size = 100;
        format_settings.binary.max_binary_string_size = 100;

        ISerialization::DeserializeBinaryBulkSettings settings;
        settings.getter = [&](ISerialization::SubstreamPath) -> ReadBuffer * { return &in; };
        settings.position_independent_encoding = false;
        settings.native_format = use_native_format;
        settings.format_settings = &format_settings;
        settings.use_specialized_prefixes_and_suffixes_substreams = use_specialized_prefixes;

        ISerialization::DeserializeBinaryBulkStatePtr state;
        serialization->deserializeBinaryBulkStatePrefix(settings, state, nullptr);

        ColumnPtr column = type->createColumn();
        serialization->deserializeBinaryBulkWithMultipleStreams(column, 0, rows, settings, state, nullptr);
    }
    catch (...)
    {
    }

    return 0;
}
