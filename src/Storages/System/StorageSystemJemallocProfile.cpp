#include "config.h"

#include <QueryPipeline/Pipe.h>
#include <Storages/System/StorageSystemJemallocProfile.h>

#if USE_JEMALLOC
#    include <ranges>
#    include <unordered_map>
#    include <unordered_set>
#    include <Columns/ColumnString.h>
#    include <Core/NamesAndTypes.h>
#    include <Core/Settings.h>
#    include <Core/SettingsEnums.h>
#    include <DataTypes/DataTypeString.h>
#    include <IO/ReadBufferFromFile.h>
#    include <IO/ReadHelpers.h>
#    include <IO/WriteBufferFromString.h>
#    include <IO/WriteHelpers.h>
#    include <Interpreters/Context.h>
#    include <Processors/ISource.h>
#    include <base/hex.h>
#    include <Common/Exception.h>
#    include <Common/FramePointers.h>
#    include <Common/Jemalloc.h>
#    include <Common/StackTrace.h>
#    include <Common/StringUtils.h>
#    include <Common/getExecutablePath.h>
#endif

namespace DB
{

#if USE_JEMALLOC
namespace
{

/// Source that reads jemalloc heap profile and outputs data
class JemallocProfileSource : public ISource
{
public:
    JemallocProfileSource(
        const std::string & filename_,
        const SharedHeader & header_,
        size_t max_block_size_,
        JemallocProfileFormat mode_,
        JemallocProfileSymbolizationMode symbolization_mode_)
        : ISource(header_)
        , filename(filename_)
        , max_block_size(max_block_size_)
        , mode(mode_)
        , symbolization_mode(symbolization_mode_)
    {
        if (mode == JemallocProfileFormat::Raw)
        {
            file_input = std::make_unique<ReadBufferFromFile>(filename);
        }
    }

    String getName() const override { return "JemallocProfile"; }

protected:
    Chunk generate() override
    {
        if (is_finished)
            return {};

        if (mode == JemallocProfileFormat::Raw)
            return generateRaw();
        else if (mode == JemallocProfileFormat::Symbolized)
            return generateSymbolized();
        else
            return generateCollapsed();
    }

private:
    enum class SymbolizedPhase
    {
        CollectingAddresses,
        OutputtingSymbolHeader,
        OutputtingSymbols,
        OutputtingHeapHeader,
        OutputtingHeap,
        Done
    };

    Chunk generateRaw()
    {
        /// Stream directly from file
        if (!file_input || file_input->eof())
        {
            is_finished = true;
            return {};
        }

        auto column = ColumnString::create();

        for (size_t rows = 0; rows < max_block_size && !file_input->eof(); ++rows)
        {
            std::string line;
            readStringUntilNewlineInto(line, *file_input);
            file_input->tryIgnore(1);

            column->insertData(line.data(), line.size());
        }

        if (file_input->eof())
            is_finished = true;

        size_t num_rows = column->size();
        Columns columns;
        columns.push_back(std::move(column));

        return Chunk(std::move(columns), num_rows);
    }

    Chunk generateSymbolized()
    {
        auto column = ColumnString::create();

        while (column->size() < max_block_size)
        {
            if (symbolized_phase == SymbolizedPhase::CollectingAddresses)
            {
                collectAddresses();
                symbolized_phase = SymbolizedPhase::OutputtingSymbolHeader;
            }

            if (symbolized_phase == SymbolizedPhase::OutputtingSymbolHeader)
            {
                /// Output symbol section header
                if (!symbol_header_line_output)
                {
                    column->insertData("--- symbol", 10);
                    symbol_header_line_output = true;
                    if (column->size() >= max_block_size)
                        break;
                }

                if (!binary_line_output)
                {
                    if (auto binary_path = getExecutablePath(); !binary_path.empty())
                    {
                        std::string binary_line = "binary=" + binary_path;
                        column->insertData(binary_line.data(), binary_line.size());
                    }
                    binary_line_output = true;
                    if (column->size() >= max_block_size)
                        break;
                }

                symbolized_phase = SymbolizedPhase::OutputtingSymbols;
            }

            if (symbolized_phase == SymbolizedPhase::OutputtingSymbols)
            {
                /// Stream symbol lines
                while (current_address_index < addresses.size() && column->size() < max_block_size)
                {
                    if (isCancelled())
                    {
                        is_finished = true;
                        break;
                    }

                    UInt64 address = addresses[current_address_index++];

                    FramePointers fp;
                    fp[0] = reinterpret_cast<void *>(address);

                    std::vector<std::string> symbols;
                    auto symbolize_callback = [&](const StackTrace::Frame & frame)
                    {
                        symbols.push_back(frame.symbol.value_or("??"));
                    };

                    bool resolve_inlines = (symbolization_mode == JemallocProfileSymbolizationMode::Regular);
                    StackTrace::forEachFrame(fp, 0, 1, symbolize_callback, /* fatal= */ resolve_inlines);

                    std::string symbol_line;
                    WriteBufferFromString out(symbol_line);
                    writePointerHex(reinterpret_cast<const void *>(address), out);

                    std::string_view separator(" ");
                    for (const auto & symbol : std::ranges::reverse_view(symbols))
                    {
                        writeString(separator, out);
                        writeString(symbol, out);
                        separator = std::string_view("--");
                    }
                    out.finalize();

                    column->insertData(symbol_line.data(), symbol_line.size());
                }

                if (current_address_index >= addresses.size())
                {
                    symbolized_phase = SymbolizedPhase::OutputtingHeapHeader;
                }
                else
                {
                    break; /// Chunk is full
                }
            }

            if (symbolized_phase == SymbolizedPhase::OutputtingHeapHeader)
            {
                if (!heap_separator_output)
                {
                    column->insertData("---", 3);
                    heap_separator_output = true;
                    if (column->size() >= max_block_size)
                        break;
                }

                if (!heap_header_output)
                {
                    column->insertData("--- heap", 8);
                    heap_header_output = true;
                    if (column->size() >= max_block_size)
                        break;
                }

                symbolized_phase = SymbolizedPhase::OutputtingHeap;
            }

            if (symbolized_phase == SymbolizedPhase::OutputtingHeap)
            {
                /// Stream heap lines from stored profile
                while (current_profile_line_index < profile_lines.size() && column->size() < max_block_size)
                {
                    const auto & line = profile_lines[current_profile_line_index++];
                    column->insertData(line.data(), line.size());
                }

                if (current_profile_line_index >= profile_lines.size())
                {
                    symbolized_phase = SymbolizedPhase::Done;
                    is_finished = true;
                }

                break; /// Chunk is full or done
            }

            if (symbolized_phase == SymbolizedPhase::Done)
            {
                is_finished = true;
                break;
            }
        }

        if (column->empty())
        {
            is_finished = true;
            return {};
        }

        size_t num_rows = column->size();
        Columns columns;
        columns.push_back(std::move(column));

        return Chunk(std::move(columns), num_rows);
    }

    void collectAddresses()
    {
        ReadBufferFromFile in(filename);

        /// Helper to parse hex address from string_view and advance it
        auto parse_hex = [](std::string_view & src) -> std::optional<UInt64>
        {
            if (src.size() >= 2 && src[0] == '0' && (src[1] == 'x' || src[1] == 'X'))
                src.remove_prefix(2);

            if (src.empty())
                return std::nullopt;

            UInt64 address = 0;
            size_t processed = 0;

            for (size_t i = 0; i < src.size() && processed < 16; ++i)
            {
                char c = src[i];
                if (isHexDigit(c))
                {
                    address = (address << 4) | unhex(c);
                    ++processed;
                }
                else
                    break;
            }

            if (processed == 0)
                return std::nullopt;

            src.remove_prefix(processed);
            return address;
        };

        std::unordered_set<UInt64> unique_addresses;
        std::string line;

        while (!in.eof())
        {
            if (isCancelled())
            {
                is_finished = true;
                return;
            }

            line.clear();
            readStringUntilNewlineInto(line, in);
            in.tryIgnore(1);

            profile_lines.push_back(line);

            if (line.empty())
                continue;

            /// Stack traces start with '@' followed by hex addresses
            if (line[0] == '@')
            {
                std::string_view line_addresses(line.data() + 1, line.size() - 1);

                bool first = true;
                while (!line_addresses.empty())
                {
                    trimLeft(line_addresses);
                    if (line_addresses.empty())
                        break;

                    auto address = parse_hex(line_addresses);
                    if (!address.has_value())
                        break;

                    unique_addresses.insert(first ? address.value() : address.value() - 1);
                    first = false;
                }
            }
        }

        /// Convert set to vector for iteration
        addresses.assign(unique_addresses.begin(), unique_addresses.end());
    }

    Chunk generateCollapsed()
    {
        /// For collapsed mode, we need to aggregate first, so we still use vector approach
        if (collapsed_lines.empty())
        {
            ReadBufferFromFile in(filename);

            auto parse_hex = [](std::string_view & src) -> std::optional<UInt64>
            {
                if (src.size() >= 2 && src[0] == '0' && (src[1] == 'x' || src[1] == 'X'))
                    src.remove_prefix(2);

                if (src.empty())
                    return std::nullopt;

                UInt64 address = 0;
                size_t processed = 0;

                for (size_t i = 0; i < src.size() && processed < 16; ++i)
                {
                    char c = src[i];
                    if (isHexDigit(c))
                    {
                        address = (address << 4) | unhex(c);
                        ++processed;
                    }
                    else
                        break;
                }

                if (processed == 0)
                    return std::nullopt;

                src.remove_prefix(processed);
                return address;
            };

            std::unordered_map<std::string, UInt64> stack_to_bytes;
            std::string line;
            std::vector<UInt64> current_stack;

            while (!in.eof())
            {
                if (isCancelled())
                {
                    is_finished = true;
                    return {};
                }

                line.clear();
                readStringUntilNewlineInto(line, in);
                in.tryIgnore(1);

                if (line.empty())
                    continue;

                if (line[0] == '@')
                {
                    current_stack.clear();
                    std::string_view line_addresses(line.data() + 1, line.size() - 1);

                    bool first = true;
                    while (!line_addresses.empty())
                    {
                        trimLeft(line_addresses);
                        if (line_addresses.empty())
                            break;

                        auto address = parse_hex(line_addresses);
                        if (!address.has_value())
                            break;

                        current_stack.push_back(first ? address.value() : address.value() - 1);
                        first = false;
                    }
                }
                else if (!current_stack.empty() && line.find(':') != std::string::npos)
                {
                    /// Parse bytes (between 2nd colon and opening bracket)
                    size_t first_colon = line.find(':');
                    size_t second_colon = line.find(':', first_colon + 1);

                    if (second_colon != std::string::npos)
                    {
                        size_t bracket_pos = line.find('[', second_colon);
                        size_t end_pos = (bracket_pos != std::string::npos) ? bracket_pos : line.size();

                        std::string_view bytes_str(line.data() + second_colon + 1, end_pos - second_colon - 1);
                        trimLeft(bytes_str);

                        UInt64 bytes = 0;
                        for (char c : bytes_str)
                        {
                            if (c >= '0' && c <= '9')
                                bytes = bytes * 10 + (c - '0');
                            else
                                break;
                        }

                        if (bytes > 0)
                        {
                            /// Symbolize stack
                            std::vector<std::string> all_symbols;

                            /// Reverse stack to get root->leaf order
                            for (UInt64 address : std::ranges::reverse_view(current_stack))
                            {
                                if (isCancelled())
                                {
                                    is_finished = true;
                                    return {};
                                }

                                /// Check cache first
                                auto cache_it = symbolization_cache.find(address);
                                if (cache_it != symbolization_cache.end())
                                {
                                    /// Use cached symbols
                                    for (const auto & symbol : cache_it->second)
                                        all_symbols.push_back(symbol);
                                }
                                else
                                {
                                    /// Symbolize and cache
                                    FramePointers fp;
                                    fp[0] = reinterpret_cast<void *>(address);

                                    std::vector<std::string> frame_symbols;
                                    auto symbolize_callback = [&](const StackTrace::Frame & frame)
                                    {
                                        frame_symbols.push_back(frame.symbol.value_or("??"));
                                    };

                                    bool resolve_inlines = (symbolization_mode == JemallocProfileSymbolizationMode::Regular);
                                    StackTrace::forEachFrame(fp, 0, 1, symbolize_callback, /* fatal= */ resolve_inlines);

                                    /// Store in cache (in reverse order for easier reuse)
                                    std::vector<std::string> cached_symbols;
                                    for (const auto & symbol : std::ranges::reverse_view(frame_symbols))
                                    {
                                        cached_symbols.push_back(symbol);
                                        all_symbols.push_back(symbol);
                                    }
                                    symbolization_cache[address] = std::move(cached_symbols);
                                }
                            }

                            /// Build collapsed stack string
                            std::string stack_str;
                            bool first_symbol = true;
                            for (const auto & symbol : all_symbols)
                            {
                                if (!first_symbol)
                                    stack_str += ';';
                                first_symbol = false;
                                stack_str += symbol;
                            }

                            /// Aggregate bytes for same stack
                            stack_to_bytes[stack_str] += bytes;
                        }
                    }

                    current_stack.clear();
                }
            }

            /// Store aggregated stacks as lines
            for (const auto & [stack, bytes] : stack_to_bytes)
            {
                collapsed_lines.push_back(stack + " " + std::to_string(bytes));
            }
        }

        /// Stream from collapsed lines
        if (current_collapsed_line_index >= collapsed_lines.size())
        {
            is_finished = true;
            return {};
        }

        auto column = ColumnString::create();

        for (size_t rows = 0; rows < max_block_size && current_collapsed_line_index < collapsed_lines.size(); ++rows)
        {
            const auto & line = collapsed_lines[current_collapsed_line_index++];
            column->insertData(line.data(), line.size());
        }

        size_t num_rows = column->size();
        Columns columns;
        columns.push_back(std::move(column));

        return Chunk(std::move(columns), num_rows);
    }

    std::string filename;
    std::unique_ptr<ReadBufferFromFile> file_input;
    size_t max_block_size;
    bool is_finished = false;
    JemallocProfileFormat mode;
    JemallocProfileSymbolizationMode symbolization_mode;

    /// For Symbolized mode streaming
    SymbolizedPhase symbolized_phase = SymbolizedPhase::CollectingAddresses;
    std::vector<UInt64> addresses;  /// Collected addresses to symbolize
    size_t current_address_index = 0;
    std::vector<std::string> profile_lines;  /// Raw profile lines for heap section
    size_t current_profile_line_index = 0;

    /// Track what we've output in header phases
    bool symbol_header_line_output = false;
    bool binary_line_output = false;
    bool heap_separator_output = false;
    bool heap_header_output = false;

    /// For Collapsed mode: processed lines (need aggregation, can't stream)
    std::vector<std::string> collapsed_lines;
    size_t current_collapsed_line_index = 0;

    /// Cache for symbolized addresses to avoid redundant symbolization
    std::unordered_map<UInt64, std::vector<std::string>> symbolization_cache;
};

}

namespace Setting
{
    extern const SettingsJemallocProfileFormat jemalloc_profile_output_format;
    extern const SettingsJemallocProfileSymbolizationMode jemalloc_profile_symbolization_mode;
}

namespace ErrorCodes
{
    extern const int NOT_IMPLEMENTED;
}

#endif

StorageSystemJemallocProfile::StorageSystemJemallocProfile(const StorageID & table_id_)
    : IStorage(table_id_)
{
    StorageInMemoryMetadata storage_metadata;
    storage_metadata.setColumns(getColumnsDescription());
    setInMemoryMetadata(storage_metadata);
}

ColumnsDescription StorageSystemJemallocProfile::getColumnsDescription()
{
    return ColumnsDescription
    {
        {"line", std::make_shared<DataTypeString>(), "Line from the symbolized jemalloc heap profile."},
    };
}

Pipe StorageSystemJemallocProfile::read(
    [[maybe_unused]] const Names & column_names,
    [[maybe_unused]] const StorageSnapshotPtr & storage_snapshot,
    SelectQueryInfo & /*query_info*/,
    [[maybe_unused]] ContextPtr context,
    QueryProcessingStage::Enum /*processed_stage*/,
    [[maybe_unused]] const size_t max_block_size,
    const size_t /*num_streams*/)
{
#if USE_JEMALLOC
    storage_snapshot->check(column_names);

    auto header = storage_snapshot->metadata->getSampleBlockWithVirtuals(getVirtualsList());

    /// Get the last flushed profile filename
    auto last_profile = std::string(Jemalloc::flushProfile("/tmp/jemalloc_clickhouse"));

    /// Get the output format from settings
    auto format = context->getSettingsRef()[Setting::jemalloc_profile_output_format];
    auto symbolization_mode = context->getSettingsRef()[Setting::jemalloc_profile_symbolization_mode];

    /// Create source that reads and processes the profile according to the format
    auto source = std::make_shared<JemallocProfileSource>(
        last_profile,
        std::make_shared<const Block>(std::move(header)),
        max_block_size,
        format,
        symbolization_mode);

    return Pipe(std::move(source));
#else
    throw Exception(ErrorCodes::NOT_IMPLEMENTED, "jemalloc is not enabled");
#endif
}

}
