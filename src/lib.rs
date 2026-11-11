pub mod codegen;
pub mod decode;
pub mod layout;
pub mod metadata;
pub mod native;
pub mod pe;
pub mod protocol;
pub mod reg;
pub mod schema;
pub mod stringpool;
pub mod type_cs;
pub mod type_index;
pub mod typesys;
pub mod wire;

pub use decode::{decode_document, decode_schema_json, decode_wrappers, DecodeOptions};
pub use metadata::Metadata;
pub use pe::PeImage;
pub use reg::{
    locate_metadata_registration, LocateOptions, LocatedRegistration, MetadataRegistration,
};
pub use schema::{
    export_bundle, read_msgpack_lz4, write_bundle, write_msgpack_lz4, ExportBundle, ExportFormat,
    SchemaDocument,
};
pub use stringpool::StringTable;
