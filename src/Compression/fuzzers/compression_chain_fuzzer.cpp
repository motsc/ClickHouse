#include <base/types.h>

#include <Compression/CompressionFactory.h>
#include <Compression/CompressionInfo.h>
#include <Compression/ICompressionCodec.h>
#include <IO/BufferWithOwnMemory.h>
#include <Interpreters/Context.h>
#include <Common/CurrentThread.h>
#include <Common/MemoryTracker.h>

#include <vector>

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

    return 0;
}

/// Input format:
///   [0]    chain_selector: selects codec chain (0-7)
///   [1..4] decompressed_size: uint32_t LE, capped at 65535
///   [5+]   compressed payload passed to the Multiple codec
///
/// The Multiple codec `doDecompressData` format (constructed from aux header):
///   source[0]            = num_codecs in chain
///   source[1..num_codecs] = CompressionMethodByte for each codec (outermost to innermost)
///   source[num_codecs+1..] = compressed payload for innermost codec (from fuzzer input)
///
/// Predefined chains (outermost codec listed first):
///   0: Delta + LZ4
///   1: Delta + Gorilla
///   2: T64 + LZ4
///   3: FPC + ZSTD
///   4: DoubleDelta + T64
///   5: Delta + ZSTD
///   6: GCD + LZ4
///   7: DoubleDelta + Gorilla
///
/// This harness exercises codec interaction bugs at chain boundaries —
/// e.g., mismatched decompressed sizes propagating from inner to outer codec.
struct AuxiliaryRandomData
{
    uint8_t chain_selector;
    uint32_t decompressed_size;
};

struct CodecChain
{
    uint8_t codecs[2];
    uint8_t num_codecs;
};

static CodecChain selectChain(uint8_t selector)
{
    constexpr uint8_t kLZ4     = static_cast<uint8_t>(CompressionMethodByte::LZ4);
    constexpr uint8_t kZSTD    = static_cast<uint8_t>(CompressionMethodByte::ZSTD);
    constexpr uint8_t kDelta   = static_cast<uint8_t>(CompressionMethodByte::Delta);
    constexpr uint8_t kT64     = static_cast<uint8_t>(CompressionMethodByte::T64);
    constexpr uint8_t kDDelta  = static_cast<uint8_t>(CompressionMethodByte::DoubleDelta);
    constexpr uint8_t kGorilla = static_cast<uint8_t>(CompressionMethodByte::Gorilla);
    constexpr uint8_t kFPC     = static_cast<uint8_t>(CompressionMethodByte::FPC);
    constexpr uint8_t kGCD     = static_cast<uint8_t>(CompressionMethodByte::GCD);

    switch (selector % 8)
    {
        case 0: return {{kDelta,  kLZ4},    2};
        case 1: return {{kDelta,  kGorilla}, 2};
        case 2: return {{kT64,    kLZ4},    2};
        case 3: return {{kFPC,    kZSTD},   2};
        case 4: return {{kDDelta, kT64},    2};
        case 5: return {{kDelta,  kZSTD},   2};
        case 6: return {{kGCD,    kLZ4},    2};
        case 7:
        default: return {{kDDelta, kGorilla}, 2};
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
        const size_t output_buffer_size = static_cast<size_t>(aux->decompressed_size % 65536);
        const CodecChain chain = selectChain(aux->chain_selector);

        data += sizeof(AuxiliaryRandomData);
        size -= sizeof(AuxiliaryRandomData);

        /// Build `CompressionCodecMultiple::doDecompressData` input:
        ///   [num_codecs, codec_byte_1, ..., codec_byte_N, payload...]
        std::vector<char> multiple_input;
        multiple_input.reserve(1 + chain.num_codecs + size);
        multiple_input.push_back(static_cast<char>(chain.num_codecs));
        for (uint8_t i = 0; i < chain.num_codecs; ++i)
            multiple_input.push_back(static_cast<char>(chain.codecs[i]));
        multiple_input.insert(
            multiple_input.end(),
            reinterpret_cast<const char *>(data),
            reinterpret_cast<const char *>(data) + size);

        auto codec = CompressionCodecFactory::instance().get(
            static_cast<uint8_t>(CompressionMethodByte::Multiple));

        DB::Memory<> memory;
        memory.resize(output_buffer_size + codec->getAdditionalSizeAtTheEndOfBuffer());

        codec->doDecompressData(
            multiple_input.data(),
            static_cast<UInt32>(multiple_input.size()),
            memory.data(),
            static_cast<UInt32>(output_buffer_size));
    }
    catch (...)
    {
    }

    return 0;
}
