# beyond-schema-dumper

Dumps [MemoryPack](https://github.com/Cysharp/MemoryPack) schema of beyond game from `global-metadata.dat` and `GameAssembly.dll`

## Usage

### Quick Start

```bash
# Build release binary
cargo build --release

# Export using game root directory (default JSON format)
beyond-schema-dumper export --game-root /path/to/game --out out/memorypack

# Export with MessagePack + LZ4 compression (greatly reduced size and fast loading)
beyond-schema-dumper export --game-root /path/to/game --out out/memorypack --format messagepack

# Or specify paths manually with verbose logging
beyond-schema-dumper export \
  --metadata /path/to/global-metadata.dat \
  --gameassembly /path/to/GameAssembly.dll \
  --out out/memorypack \
  --format msgpack \
  -v
```

### CLI Help

```text
Dumps MemoryPack schema of beyond game from global-metadata.dat and GameAssembly.dll

Usage: beyond-schema-dumper <COMMAND>

Commands:
  export  Write schemas, type_index, union-map, unmanaged, enums, type.cs, README.md

Options:
  -h, --help     Print help
  -V, --version  Print version
```

`export` subcommand:

```text
Write schemas, type_index, union-map, unmanaged, enums, type.cs, README.md

Usage: beyond-schema-dumper export [OPTIONS]

Options:
      --metadata <METADATA>          global-metadata.dat path
      --gameassembly <GAMEASSEMBLY>  Windows GameAssembly.dll path
      --game-root <GAME_ROOT>        Game root or handoff folder
      --out <OUT>                    Output directory [default: out/memorypack]
      --format <FORMAT>              Export format: json (default) or messagepack (msgpack, with lz4 compression) [default: json] [possible values: json, messagepack]
      --scan                         Scan .rdata instead of using known MetadataRegistration RVA
  -v, --verbose                      Verbose diagnostic output
  -h, --help                         Print help
```

## Schema

The export folder contains all metadata required for offline deserialization:

| File | Description |
|---|---|
| `schemas.{json\|msgpack.lz4}` | All `*ForMemoryPack` wrapper schema definitions. The critical **`wire_order`** field defines the actual binary serialization sequence. |
| `type_index.{json\|msgpack.lz4}` | Index mapping virtual file basenames (`by_basename`) and full type names (`by_type`) to wrapper types. |
| `union-map.{json\|msgpack.lz4}` | Polymorphic union mapping tables (`static_type` -> `tag` -> `concrete_type`), recovered from native jumptables. |
| `unmanaged.{json\|msgpack.lz4}` | Blittable value types and their payload sizes for direct memory-copy (`memcpy`) deserialization. |
| `enums.{json\|msgpack.lz4}` | Underlying byte widths of enums (extracted from metadata `value__`). |
| `type.cs` | Compact C# pseudo-class definitions with fields sorted by `wire_order` for human inspection. |

### MessagePack + LZ4 Decompression Guide

When `--format messagepack` (or `msgpack`) is used, artifacts are serialized via MessagePack (named map structure) and compressed using `MessagePack-CSharp`'s native `Lz4Block` format (MessagePack Extension TypeCode 99).

#### C# Integration (MessagePack-CSharp)

Decompress directly using [MessagePack-CSharp](https://github.com/MessagePack-CSharp/MessagePack-CSharp) with **zero extra dependencies**:

```csharp
// NuGet package: MessagePack
using MessagePack;

var options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4Block);

using var fileStream = File.OpenRead("schemas.msgpack.lz4");
var schemas = MessagePackSerializer.Deserialize<Dictionary<string, object>>(fileStream, options);
```

#### Python Integration

```python
# pip install lz4 msgpack
import lz4.block
import msgpack

with open("schemas.msgpack.lz4", "rb") as f:
    data = f.read()

# Parse MessagePack Extension header (ext 16 / ext 32 with TypeCode 99)
offset = 4 if data[0] == 0xc8 else 6
# Read 4-byte uncompressed size after 0xd2 (int32 format)
uncompressed_size = int.from_bytes(data[offset + 1:offset + 5], "big")
decompressed = lz4.block.decompress(data[offset + 5:], uncompressed_size=uncompressed_size)
schemas = msgpack.unpackb(decompressed, raw=False)
```

### Deserialization Guide

1. **Locate Schema**: Given a data file basename (e.g., `BambooRaftTaskTable.json`), look up `type_index["by_basename"]["BambooRaftTaskTable"]` to get the target wrapper schema in `schemas`.
2. **Read Object Header**: Each MemoryPack object begins with a 1-byte member count (`memberCount`):
   - `255` (`0xFF`): `null` object.
   - `250` (`0xFA`): wide object, followed by an `int32` representing the true member count.
   - Any other value: member count.
3. **Read Members Sequentially in `wire_order`**:
   > **Important**: Always follow `wire_order` (the wrapper property order), **not** the target C# class field declaration order (`members_from_target_fields`).
   - **Primitives** (`bool`, `int`, `float`, `double`, etc.): Little-endian bytes.
   - **Strings**: Default to an `int32` StringPool ID (`-1` = empty, `-2` = null), resolved against `StringPool*.byte`. (Inline UTF-8 only when marked with `collection_encoding: "utf8"`).
   - **Enums**: Read using the byte width specified in `enums`.
   - **Lists / Arrays**: Read an `int32` element count (`-1` = null), followed by elements. If marked `memcpy` in `unmanaged`, directly copy `count * payload_size` bytes.
   - **Dictionaries**: Read an `int32` count (`-1` = null), followed by sequential key-value pairs.
   - **Nested Objects**: Recursively decode the object header and members.
   - **Polymorphic / Union Types**: Read the integer tag and resolve the concrete child type using `union-map`.

## Best Practice

- [BydTools](https://github.com/SherkeyXD/BydTools)
