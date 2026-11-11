use crate::codegen;
use crate::layout::{self, EnumLayout, TypeLayouts, UnmanagedLayout};
use crate::metadata::{Metadata, TypeDefinition};
use crate::native::{self, UnionTable};
use crate::pe::PeImage;
use crate::protocol::{self, ProtocolDocument};
use crate::reg::{load_field_offsets, MetadataRegistration};
use crate::type_cs::render_type_cs;
use crate::type_index::build_type_index;
use crate::typesys::{field_attrs, TypeEnum, TypeSystem};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub const WIRE_ORDER_SOURCE: &str =
    "wrapper __name__ property metadata order (confirmed = native Deserialize call order)";

pub const ORDER_NOTE: &str = "wire_order / members_from_wrapper_props is the canonical binary \
member order (GameAssembly Deserialize matches these setters, often alphabetical). \
members_from_target_fields is declaration/layout order only — NOT wire order.";

pub const TARGET_FIELD_NOTE: &str =
    "reference only — instance field declaration / offset layout; NOT MemoryPack wire order";

pub const PURPOSE: &str = "Beyond.MemoryPack offline schema for packed config decryption";

pub const CUSTOM_ATTRIBUTES_NOTE: &str =
    "not used — AttributeDataRange is MethodDef index lists, not classic CA blobs";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberProp {
    pub name: String,
    pub raw_property: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub property_index: usize,
    pub has_getter: bool,
    pub has_setter: bool,
    /// Native `T[]` / `List<T>` encoding for this field. `memcpy` = i32 count then
    /// `count * payload_size` with no per-element object header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub field_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
    pub is_public: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperSchema {
    pub wrapper_type: String,
    pub typedef_index: usize,
    pub assembly: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_typedef_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_assembly: Option<String>,
    pub interfaces: Vec<String>,
    /// Canonical wire / binary member order (= wrapper `__prop__` metadata order).
    pub wire_order: Vec<MemberProp>,
    /// Alias of `wire_order`.
    pub members_from_wrapper_props: Vec<MemberProp>,
    /// Target instance fields in declaration order. Not wire order.
    pub members_from_target_fields: Vec<MemberField>,
    pub orders_differ: bool,
    pub has_formatter: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatter_typedef: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatter_type: Option<String>,
    pub has_deserialize: bool,
    pub has_register_formatter: bool,
    pub wire_order_source: String,
    pub order_note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_typedef_index: Option<usize>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub wire_includes_base: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_member_count: Option<i32>,
    /// `has_deserialize` is false and at least one wrapper lists this target as `parent_type`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_union_base: bool,
    /// Nested `T+TFormatter` MemoryPack wire (UTF-8 strings). Used when a
    /// wrapper field is native `ReadValue<T>` rather than the Beyond wrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memorypack_wire: Option<Vec<MemberProp>>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkerSchema {
    pub type_name: String,
    pub typedef_index: usize,
    pub assembly: String,
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_wrapper: Option<String>,
    pub instance_field_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counts {
    pub wrappers: usize,
    pub serialize_markers: usize,
    pub wrappers_orders_differ_from_target_fields: usize,
    pub wrappers_with_formatter: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedExports {
    pub type_index: String,
    #[serde(default)]
    pub type_cs: String,
    pub readme: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enums: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unmanaged: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unions: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub union_map: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDocument {
    pub generated_by: String,
    pub purpose: String,
    pub wire_order_rule: String,
    pub order_caveat: String,
    pub custom_attributes: String,
    pub related_exports: RelatedExports,
    pub counts: Counts,
    pub wrappers: Vec<WrapperSchema>,
    pub serialize_markers: Vec<MarkerSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol_ops: Vec<protocol::ProtocolOp>,
}

#[derive(Debug)]
pub struct ExportBundle {
    pub schemas: SchemaDocument,
    pub type_index: serde_json::Value,
    pub type_cs: String,
    pub readme: String,
    pub protocol: ProtocolDocument,
    pub enums: Vec<EnumLayout>,
    pub unmanaged: Vec<UnmanagedLayout>,
    pub unions: Vec<UnionTable>,
    pub union_map: BTreeMap<String, BTreeMap<String, String>>,
    pub missing: serde_json::Value,
}

pub fn export_bundle(
    meta: &Metadata,
    pe: &PeImage,
    reg: &MetadataRegistration,
    reg_source: &str,
) -> Result<ExportBundle> {
    let protocol = protocol::build_protocol(pe);
    let (mut schemas, layouts, unions) = build_schema_document(meta, pe, reg)?;
    schemas.protocol_ops = protocol.ops.clone();
    let type_index = build_type_index(&schemas.wrappers, &schemas.serialize_markers, &layouts);
    let type_cs = render_type_cs(&schemas);
    let union_map = native::decoder_union_map(&unions);
    let readme = output_readme(&schemas.counts, &unions, reg_source);
    let missing = collect_missing(&schemas.wrappers, &layouts, &unions);
    Ok(ExportBundle {
        schemas,
        type_index,
        type_cs,
        readme,
        protocol,
        enums: layouts.enums.values().cloned().collect(),
        unmanaged: layouts.unmanaged.values().cloned().collect(),
        unions,
        union_map,
        missing,
    })
}

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    clap::ValueEnum,
    Debug,
    Default,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Json,
    #[value(alias = "msgpack")]
    Messagepack,
}

impl ExportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Messagepack => "msgpack.lz4",
        }
    }
}

pub fn write_bundle(
    bundle: &ExportBundle,
    out_dir: &Path,
    format: ExportFormat,
) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let ext = format.extension();
    let schemas_path = out_dir.join(format!("schemas.{}", ext));
    let index_path = out_dir.join(format!("type_index.{}", ext));
    let protocol_path = out_dir.join(format!("protocol.{}", ext));
    let enums_path = out_dir.join(format!("enums.{}", ext));
    let unmanaged_path = out_dir.join(format!("unmanaged.{}", ext));
    let unions_path = out_dir.join(format!("unions.{}", ext));
    let union_map_path = out_dir.join(format!("union-map.{}", ext));
    let missing_path = out_dir.join(format!("missing.{}", ext));
    let cs_path = out_dir.join("type.cs");
    let readme_path = out_dir.join("README.md");

    match format {
        ExportFormat::Json => {
            write_json(&schemas_path, &bundle.schemas)?;
            write_json(&index_path, &bundle.type_index)?;
            write_json(&protocol_path, &bundle.protocol)?;
            write_json(&enums_path, &bundle.enums)?;
            write_json(&unmanaged_path, &bundle.unmanaged)?;
            write_json(&unions_path, &bundle.unions)?;
            write_json(&union_map_path, &bundle.union_map)?;
            write_json(&missing_path, &bundle.missing)?;
        }
        ExportFormat::Messagepack => {
            write_msgpack_lz4(&schemas_path, &bundle.schemas)?;
            write_msgpack_lz4(&index_path, &bundle.type_index)?;
            write_msgpack_lz4(&protocol_path, &bundle.protocol)?;
            write_msgpack_lz4(&enums_path, &bundle.enums)?;
            write_msgpack_lz4(&unmanaged_path, &bundle.unmanaged)?;
            write_msgpack_lz4(&unions_path, &bundle.unions)?;
            write_msgpack_lz4(&union_map_path, &bundle.union_map)?;
            write_msgpack_lz4(&missing_path, &bundle.missing)?;
        }
    }
    fs::write(&cs_path, &bundle.type_cs).with_context(|| format!("write {}", cs_path.display()))?;
    let mut f =
        File::create(&readme_path).with_context(|| format!("create {}", readme_path.display()))?;
    f.write_all(bundle.readme.as_bytes())?;
    Ok(vec![
        schemas_path,
        index_path,
        protocol_path,
        enums_path,
        unmanaged_path,
        unions_path,
        union_map_path,
        missing_path,
        cs_path,
        readme_path,
    ])
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut writer, value)
        .with_context(|| format!("write {}", path.display()))?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

pub fn write_msgpack_lz4<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let f = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = BufWriter::new(f);

    let mut raw_bytes = Vec::new();
    let mut ser = rmp_serde::Serializer::new(&mut raw_bytes).with_struct_map();
    value
        .serialize(&mut ser)
        .with_context(|| format!("serialize msgpack {}", path.display()))?;

    let uncompressed_len = raw_bytes.len() as u32;
    let compressed_block = lz4_flex::block::compress(&raw_bytes);

    let ext_payload_len = 5 + compressed_block.len();

    if ext_payload_len <= 0xff {
        writer.write_all(&[0xc7, ext_payload_len as u8, 0x63])?;
    } else if ext_payload_len <= 0xffff {
        writer.write_all(&[0xc8])?;
        writer.write_all(&(ext_payload_len as u16).to_be_bytes())?;
        writer.write_all(&[0x63])?;
    } else {
        writer.write_all(&[0xc9])?;
        writer.write_all(&(ext_payload_len as u32).to_be_bytes())?;
        writer.write_all(&[0x63])?;
    }

    writer.write_all(&[0xd2])?;
    writer.write_all(&uncompressed_len.to_be_bytes())?;
    writer.write_all(&compressed_block)?;
    writer.flush()?;
    Ok(())
}

pub fn read_msgpack_lz4<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    use std::io::Read;
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .with_context(|| format!("read {}", path.display()))?;

    if data.len() >= 6 {
        let (ext_type, payload_offset) = match data[0] {
            0xc7 => (data[2], 3),
            0xc8 => (data[3], 4),
            0xc9 => (data[5], 6),
            _ => (0, 0),
        };

        if ext_type == 99 && payload_offset + 5 <= data.len() && data[payload_offset] == 0xd2 {
            let len_bytes: [u8; 4] = data[payload_offset + 1..payload_offset + 5]
                .try_into()
                .unwrap();
            let uncompressed_len = u32::from_be_bytes(len_bytes) as usize;
            let compressed_block = &data[payload_offset + 5..];
            let decompressed = lz4_flex::block::decompress(compressed_block, uncompressed_len)
                .map_err(|e| anyhow::anyhow!("lz4 block decompress failed: {e}"))?;
            let val: T = rmp_serde::from_slice(&decompressed)
                .with_context(|| format!("deserialize msgpack {}", path.display()))?;
            return Ok(val);
        }
    }

    if data.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        let decoder = lz4_flex::frame::FrameDecoder::new(&data[..]);
        let val: T = rmp_serde::from_read(decoder)
            .with_context(|| format!("deserialize msgpack frame {}", path.display()))?;
        return Ok(val);
    }

    let val: T = rmp_serde::from_slice(&data)
        .with_context(|| format!("deserialize plain msgpack {}", path.display()))?;
    Ok(val)
}

pub fn build_schema_document(
    meta: &Metadata,
    pe: &PeImage,
    reg: &MetadataRegistration,
) -> Result<(SchemaDocument, TypeLayouts, Vec<UnionTable>)> {
    let mut ts = TypeSystem::load(pe, meta, reg.types, reg.types_count)?;
    let field_counts: Vec<u16> = meta.type_defs.iter().map(|td| td.field_count).collect();
    let field_offs = load_field_offsets(pe, &field_counts, reg);
    let type_sizes = layout::load_type_sizes(pe, reg);
    let instance_size: Vec<i32> = type_sizes.iter().map(|s| s.instance_size).collect();
    let td_image = build_td_image_map(meta);

    let mut wrappers = Vec::new();
    let mut wrapper_by_target: HashMap<usize, String> = HashMap::new();
    let mut target_name_by_td: BTreeMap<usize, String> = BTreeMap::new();
    let mut target_name_by_wrapper_td: BTreeMap<usize, String> = BTreeMap::new();

    for (ti, td) in meta.type_defs.iter().enumerate() {
        let name = meta.string(td.name_index).unwrap_or_else(|_| "?".into());
        if !name.ends_with("ForMemoryPack") || name.contains("Formatter") {
            continue;
        }
        let full = meta.type_name(td).unwrap_or_else(|_| name.clone());
        let ifaces: Vec<String> = meta
            .interfaces_of(td)
            .into_iter()
            .map(|ix| ts.name_of_index(ix))
            .collect();
        let schema = build_wrapper_schema(
            meta,
            &mut ts,
            &field_offs,
            &instance_size,
            &td_image,
            ti,
            td,
            &full,
            &ifaces,
        );
        if let Some(tidx) = schema.target_typedef_index {
            wrapper_by_target.insert(tidx, schema.wrapper_type.clone());
            if let Some(tname) = schema.target_type.clone() {
                target_name_by_td.insert(tidx, tname.clone());
                target_name_by_wrapper_td.insert(ti, tname);
            }
        }
        wrappers.push(schema);
    }

    apply_inherited_wire(&mut wrappers, &ts, &instance_size);

    let mut referenced = HashSet::new();
    for w in &wrappers {
        for m in &w.wire_order {
            collect_type_names(&m.ty, &mut referenced);
        }
        if let Some(t) = &w.target_type {
            referenced.insert(t.clone());
        }
    }
    let mut layouts = layout::collect_layouts(meta, &mut ts, &field_offs, &type_sizes, &referenced);

    let code = codegen::load_code_map(pe, meta).unwrap_or_default();
    let native = native::analyze(
        pe,
        meta,
        &mut ts,
        &code,
        &wrapper_by_target
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect(),
        &target_name_by_td,
        &target_name_by_wrapper_td,
    );
    apply_native_member_counts(&mut wrappers, &native.member_counts);
    apply_collection_encodings(&mut layouts.unmanaged, &mut wrappers, &native.array_strides);
    apply_optional_encodings(&layouts.unmanaged, &mut wrappers, &native.struct_memcpy);
    apply_memorypack_value_encodings(&mut wrappers, &native.memorypack_wires);
    apply_vector3_struct_formatters(&layouts.unmanaged, &mut wrappers);
    mark_union_bases(&mut wrappers);
    let unions = native.unions;

    let mut markers = Vec::new();
    for (ti, td) in meta.type_defs.iter().enumerate() {
        let name = meta.string(td.name_index).unwrap_or_else(|_| "?".into());
        if name.ends_with("ForMemoryPack") {
            continue;
        }
        let ifaces: Vec<String> = meta
            .interfaces_of(td)
            .into_iter()
            .map(|ix| ts.name_of_index(ix))
            .collect();
        if !ifaces.iter().any(|i| is_serialize_marker_iface(i)) {
            continue;
        }
        let full = ts.typedef_full_name(ti as i32);
        markers.push(MarkerSchema {
            type_name: full,
            typedef_index: ti,
            assembly: td_image.get(ti).cloned().unwrap_or_default(),
            interfaces: ifaces,
            matching_wrapper: wrapper_by_target.get(&ti).cloned(),
            instance_field_count: count_instance_fields(meta, &ts, td),
        });
    }

    wrappers.sort_by(|a, b| a.wrapper_type.cmp(&b.wrapper_type));
    markers.sort_by(|a, b| a.type_name.cmp(&b.type_name));

    let counts = Counts {
        wrappers: wrappers.len(),
        serialize_markers: markers.len(),
        wrappers_orders_differ_from_target_fields: wrappers
            .iter()
            .filter(|w| w.orders_differ)
            .count(),
        wrappers_with_formatter: wrappers.iter().filter(|w| w.has_formatter).count(),
    };

    Ok((
        SchemaDocument {
            generated_by: "beyond-schema-dumper".into(),
            purpose: PURPOSE.into(),
            wire_order_rule: WIRE_ORDER_SOURCE.into(),
            order_caveat: ORDER_NOTE.into(),
            custom_attributes: CUSTOM_ATTRIBUTES_NOTE.into(),
            related_exports: RelatedExports {
                type_index: "type_index.json".into(),
                type_cs: "type.cs".into(),
                readme: "README.md".into(),
                protocol: "protocol.json".into(),
                enums: "enums.json".into(),
                unmanaged: "unmanaged.json".into(),
                unions: "unions.json".into(),
                union_map: "union-map.json".into(),
                note: "protocol.json is the read contract. schemas.json wire_order is the binary member order including inherited and underscore members. Field collection_encoding is memcpy / formatter / memorypack / utf8. enums.json / unmanaged.json / unions.json / union-map.json are required to decode without type-name branches. missing.json lists referenced types with no declared rule.".into(),
            },
            counts,
            wrappers,
            serialize_markers: markers,
            protocol_ops: Vec::new(),
        },
        layouts,
        unions,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_wrapper_schema(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    field_offs: &HashMap<(usize, usize), i32>,
    _instance_size: &[i32],
    td_image: &[String],
    ti: usize,
    td: &TypeDefinition,
    full: &str,
    ifaces: &[String],
) -> WrapperSchema {
    let assembly = td_image.get(ti).cloned().unwrap_or_default();
    let (target_type, target_typedef_index) = resolve_wrapper_target(meta, ts, td, ifaces);
    let target_assembly = target_typedef_index.and_then(|i| td_image.get(i).cloned());
    let (parent_type, parent_typedef_index) = target_typedef_index
        .and_then(|tidx| parent_info(ts, tidx))
        .unwrap_or((None, None));

    let props = collect_wrapper_props(meta, ts, td);
    let fields = if let Some(tidx) = target_typedef_index {
        collect_target_fields(meta, ts, field_offs, tidx)
    } else {
        Vec::new()
    };
    let orders_differ = orders_differ(&props, &fields);
    let (has_formatter, formatter_typedef, formatter_type) = find_nested_formatter(meta, td);
    let (has_deserialize, has_register_formatter) = method_flags(meta, td);

    WrapperSchema {
        wrapper_type: full.to_string(),
        typedef_index: ti,
        assembly,
        target_type,
        target_typedef_index,
        target_assembly,
        interfaces: ifaces.to_vec(),
        members_from_wrapper_props: props.clone(),
        wire_order: props,
        members_from_target_fields: fields,
        orders_differ,
        has_formatter,
        formatter_typedef,
        formatter_type,
        has_deserialize,
        has_register_formatter,
        wire_order_source: WIRE_ORDER_SOURCE.into(),
        order_note: ORDER_NOTE.into(),
        parent_type,
        parent_typedef_index,
        wire_includes_base: false,
        native_member_count: None,
        is_union_base: false,
        memorypack_wire: None,
    }
}

fn collect_wrapper_props(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    td: &TypeDefinition,
) -> Vec<MemberProp> {
    let mut out = Vec::new();
    if td.property_count == 0 || td.property_index < 0 {
        return out;
    }
    let start = td.property_index as usize;
    for (local, pi) in (start..start + td.property_count as usize).enumerate() {
        let Some(p) = meta.properties.get(pi) else {
            break;
        };
        let raw = meta.string(p.name_index).unwrap_or_else(|_| "?".into());
        let Some(stripped) = strip_dunder(&raw) else {
            continue;
        };
        if stripped == "instance" {
            continue;
        }
        let ty = property_type_name(meta, ts, td, p.get, p.set);
        out.push(MemberProp {
            name: stripped,
            raw_property: raw,
            ty,
            property_index: local,
            has_getter: p.get >= 0,
            has_setter: p.set >= 0,
            collection_encoding: None,
        });
    }
    out
}

fn collect_target_fields(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    field_offs: &HashMap<(usize, usize), i32>,
    tidx: usize,
) -> Vec<MemberField> {
    let mut out = Vec::new();
    let Some(td) = meta.type_defs.get(tidx) else {
        return out;
    };
    if td.field_count == 0 || td.field_index < 0 {
        return out;
    }
    let start = td.field_index as usize;
    for (local, fi) in (start..start + td.field_count as usize).enumerate() {
        let Some(f) = meta.fields.get(fi) else {
            break;
        };
        let attrs = ts.attrs_of_index(f.type_index);
        if attrs & field_attrs::STATIC != 0 || attrs & field_attrs::LITERAL != 0 {
            continue;
        }
        let name = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
        let ty = ts.name_of_index(f.type_index);
        let is_public = (attrs & field_attrs::FIELD_ACCESS_MASK) == field_attrs::PUBLIC;
        out.push(MemberField {
            name,
            ty,
            field_index: local,
            offset: field_offs.get(&(tidx, local)).copied(),
            is_public,
            note: TARGET_FIELD_NOTE.into(),
        });
    }
    out
}

fn count_instance_fields(meta: &Metadata, ts: &TypeSystem<'_>, td: &TypeDefinition) -> usize {
    if td.field_count == 0 || td.field_index < 0 {
        return 0;
    }
    let start = td.field_index as usize;
    let mut n = 0;
    for fi in start..start + td.field_count as usize {
        let Some(f) = meta.fields.get(fi) else {
            break;
        };
        let attrs = ts.attrs_of_index(f.type_index);
        if attrs & field_attrs::STATIC == 0 && attrs & field_attrs::LITERAL == 0 {
            n += 1;
        }
    }
    n
}

pub fn orders_differ(props: &[MemberProp], fields: &[MemberField]) -> bool {
    if props.is_empty() || fields.is_empty() {
        return false;
    }
    let pn: Vec<&str> = props.iter().map(|m| m.name.as_str()).collect();
    let fnames: Vec<&str> = fields.iter().map(|m| m.name.as_str()).collect();
    if pn.len() != fnames.len() {
        return true;
    }
    let mut a = pn.clone();
    let mut b = fnames.clone();
    a.sort_unstable();
    b.sort_unstable();
    if a != b {
        return true;
    }
    pn != fnames
}

fn resolve_wrapper_target(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    td: &TypeDefinition,
    ifaces: &[String],
) -> (Option<String>, Option<usize>) {
    for iface_ix in meta.interfaces_of(td) {
        if let Some((tname, tidx)) = generic_wrapper_target(ts, iface_ix) {
            return (Some(tname), tidx);
        }
    }
    for iface in ifaces {
        if let Some(inner) = extract_wrapper_targ(iface) {
            let tidx = find_typedef_by_simple_name(meta, &inner);
            return (Some(inner), tidx);
        }
    }
    let leaf = meta.string(td.name_index).unwrap_or_default();
    if let Some(rest) = leaf.strip_suffix("ForMemoryPack") {
        if let Some(simple) = rest.rsplit('_').next() {
            if !simple.is_empty() {
                let tidx = find_typedef_by_simple_name(meta, simple);
                return (Some(simple.to_string()), tidx);
            }
        }
    }
    (None, None)
}

fn generic_wrapper_target(
    ts: &mut TypeSystem<'_>,
    iface_type_index: i32,
) -> Option<(String, Option<usize>)> {
    let t = ts.type_at_index(iface_type_index).ok()?;
    if TypeEnum::from_u8(t.type_enum()) != TypeEnum::GenericInst {
        return None;
    }
    let (base_leaf, arg_indices) = generic_inst_leaf_and_arg_indices(ts, t.data)?;
    if !base_leaf.starts_with("IMemoryPackDeSerializeWrapper") {
        return None;
    }
    let arg0 = *arg_indices.first()?;
    let tidx = ts.typedef_index_of(arg0).map(|i| i as usize);
    let tname = ts.name_of_index(arg0);
    Some((tname, tidx))
}

/// Resolve GenericInst → (base type leaf name, type-table indices of args).
fn generic_inst_leaf_and_arg_indices(
    ts: &TypeSystem<'_>,
    generic_class_va: u64,
) -> Option<(String, Vec<i32>)> {
    let type_va = ts.pe.read_u64_va(generic_class_va)?;
    let class_inst_va = ts.pe.read_u64_va(generic_class_va + 8)?;
    let base_ty = ts.read_type_at_va(type_va).ok()?;
    let base_leaf = match TypeEnum::from_u8(base_ty.type_enum()) {
        TypeEnum::Class | TypeEnum::ValueType | TypeEnum::TypeIndex => {
            let idx = base_ty.klass_index();
            ts.meta
                .type_defs
                .get(idx as usize)
                .and_then(|td| ts.meta.string(td.name_index).ok())
                .unwrap_or_else(|| format!("/*td:{idx}*/"))
        }
        _ => return None,
    };
    if class_inst_va == 0 {
        return Some((base_leaf, Vec::new()));
    }
    let argc = ts.pe.read_u64_va(class_inst_va)? as usize;
    let argv = ts.pe.read_u64_va(class_inst_va + 8)?;
    let mut args = Vec::with_capacity(argc.min(16));
    for i in 0..argc.min(16) {
        let arg_ty_va = ts.pe.read_u64_va(argv + (i as u64) * 8)?;
        let idx = ts.type_ptrs.iter().position(|&p| p == arg_ty_va)? as i32;
        args.push(idx);
    }
    Some((base_leaf, args))
}

fn find_nested_formatter(
    meta: &Metadata,
    td: &TypeDefinition,
) -> (bool, Option<usize>, Option<String>) {
    for child in meta.nested_children(td) {
        let ctd = &meta.type_defs[child];
        let cname = meta.string(ctd.name_index).unwrap_or_default();
        if cname.contains("Formatter") {
            let full = meta.type_name(ctd).unwrap_or(cname);
            return (true, Some(child), Some(full));
        }
    }
    (false, None, None)
}

fn method_flags(meta: &Metadata, td: &TypeDefinition) -> (bool, bool) {
    let mut has_deser = false;
    let mut has_reg = false;
    if td.method_count == 0 || td.method_index < 0 {
        return (false, false);
    }
    let start = td.method_index as usize;
    for mi in start..start + td.method_count as usize {
        let Some(m) = meta.methods.get(mi) else {
            break;
        };
        let n = meta.string(m.name_index).unwrap_or_default();
        if n == "Deserialize" {
            has_deser = true;
        }
        if n == "RegisterFormatter" {
            has_reg = true;
        }
    }
    (has_deser, has_reg)
}

fn strip_dunder(raw: &str) -> Option<String> {
    let s = raw.strip_prefix("__")?.strip_suffix("__")?;
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

fn is_serialize_marker_iface(name: &str) -> bool {
    let leaf = name.rsplit('.').next().unwrap_or(name);
    leaf == "IMemoryPackSerialize" || leaf.starts_with("IMemoryPackSerialize`")
}

fn extract_wrapper_targ(iface: &str) -> Option<String> {
    let leaf = iface.rsplit('.').next().unwrap_or(iface);
    if !leaf.starts_with("IMemoryPackDeSerializeWrapper") {
        return None;
    }
    let open = leaf.find('<')?;
    let close = leaf.rfind('>')?;
    if close <= open + 1 {
        return None;
    }
    Some(leaf[open + 1..close].to_string())
}

fn find_typedef_by_simple_name(meta: &Metadata, simple: &str) -> Option<usize> {
    for (i, td) in meta.type_defs.iter().enumerate() {
        let Ok(n) = meta.string(td.name_index) else {
            continue;
        };
        if n == simple && !n.ends_with("ForMemoryPack") && !n.contains("Formatter") {
            return Some(i);
        }
    }
    None
}

fn parent_info(
    ts: &mut TypeSystem<'_>,
    target_td: usize,
) -> Option<(Option<String>, Option<usize>)> {
    let parent_index = ts.meta.type_defs.get(target_td)?.parent_index;
    if parent_index < 0 {
        return None;
    }
    let name = ts.name_of_index(parent_index);
    if layout::skip_parent_name(&name) || name.contains("/*") {
        return None;
    }
    let parent_td = ts.typedef_index_of(parent_index).map(|i| i as usize);
    Some((Some(name), parent_td))
}

fn apply_inherited_wire(
    wrappers: &mut [WrapperSchema],
    ts: &TypeSystem<'_>,
    instance_size: &[i32],
) {
    let by_target: HashMap<usize, usize> = wrappers
        .iter()
        .enumerate()
        .filter_map(|(i, w)| w.target_typedef_index.map(|t| (t, i)))
        .collect();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut name_ambiguous = HashSet::new();
    for (i, w) in wrappers.iter().enumerate() {
        let Some(name) = w.target_type.as_ref() else {
            continue;
        };
        if name_ambiguous.contains(name) {
            continue;
        }
        if by_name.insert(name.clone(), i).is_some() {
            by_name.remove(name);
            name_ambiguous.insert(name.clone());
        }
    }
    // Closed generic parents (BlackboardInt → ParamBase<int,int>) and
    // NodeBase under an overlapping ActionBase must settle in parent-first
    // order. Repeat until the wires stop growing.
    for _ in 0..8 {
        let wires: Vec<Vec<MemberProp>> = wrappers.iter().map(|w| w.wire_order.clone()).collect();
        let mut changed = false;
        for i in 0..wrappers.len() {
            let Some(tidx) = wrappers[i].target_typedef_index else {
                continue;
            };
            let min_off = wrappers[i]
                .members_from_target_fields
                .iter()
                .filter_map(|f| f.offset)
                .min();
            let chain = base_chain(ts, instance_size, tidx, min_off);
            let mut merged = Vec::new();
            let mut seen = HashSet::new();
            for base_td in chain {
                let Some(&wi) = by_target.get(&base_td) else {
                    continue;
                };
                for m in &wires[wi] {
                    if seen.insert(m.name.clone()) {
                        merged.push(m.clone());
                    }
                }
            }
            if let Some(pname) = wrappers[i].parent_type.as_ref() {
                if let Some(&wi) = by_name.get(pname) {
                    for m in &wires[wi] {
                        if seen.insert(m.name.clone()) {
                            merged.push(m.clone());
                        }
                    }
                }
            }
            for m in &wires[i] {
                if seen.insert(m.name.clone()) {
                    merged.push(m.clone());
                }
            }
            if merged.len() > wrappers[i].wire_order.len() {
                wrappers[i].wire_includes_base = true;
                wrappers[i].wire_order = merged.clone();
                wrappers[i].members_from_wrapper_props = merged;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn base_chain(
    ts: &TypeSystem<'_>,
    instance_size: &[i32],
    target_td: usize,
    derived_min_offset: Option<i32>,
) -> Vec<usize> {
    let mut chain = Vec::new();
    let mut current = target_td as i32;
    for _ in 0..8 {
        let Some(parent) = ts.next_parent_typedef(current) else {
            break;
        };
        let name = ts.typedef_full_name(parent);
        if layout::skip_parent_name(&name) {
            break;
        }
        let parent_size = instance_size.get(parent as usize).copied().unwrap_or(0);
        if let Some(min_off) = derived_min_offset {
            if min_off < parent_size && min_off > 0 {
                // Own fields sit inside this parent's instance (ActionBase
                // runtime fields after NodeBase). Skip it, keep walking to
                // ancestors that still fit — NodeBase at size 96 with min 96.
                current = parent;
                continue;
            }
        }
        chain.push(parent as usize);
        current = parent;
    }
    chain.reverse();
    chain
}

fn mark_union_bases(wrappers: &mut [WrapperSchema]) {
    let parents: HashSet<String> = wrappers
        .iter()
        .filter_map(|w| w.parent_type.clone())
        .collect();
    for w in wrappers {
        if w.has_deserialize {
            continue;
        }
        if let Some(target) = &w.target_type {
            if parents.contains(target) {
                w.is_union_base = true;
            }
        }
    }
}

fn strides_for_wrapper(
    w: &WrapperSchema,
    array_strides: &BTreeMap<String, std::collections::BTreeSet<i32>>,
) -> std::collections::BTreeSet<i32> {
    let mut out = std::collections::BTreeSet::new();
    if let Some(s) = array_strides.get(&w.wrapper_type) {
        out.extend(s.iter().copied());
    }
    if let Some(fmt) = &w.formatter_type {
        if let Some(s) = array_strides.get(fmt) {
            out.extend(s.iter().copied());
        }
    }
    let wrapper_leaf = w
        .wrapper_type
        .rsplit(['.', '+'])
        .next()
        .unwrap_or(&w.wrapper_type);
    let fmt_leaf = w
        .formatter_type
        .as_deref()
        .map(|s| s.rsplit(['.', '+']).next().unwrap_or(s));
    for (name, strides) in array_strides {
        let leaf = name.rsplit(['.', '+']).next().unwrap_or(name);
        if leaf == wrapper_leaf || fmt_leaf == Some(leaf) {
            out.extend(strides.iter().copied());
        }
    }
    out
}

fn apply_collection_encodings(
    unmanaged: &mut BTreeMap<String, UnmanagedLayout>,
    wrappers: &mut [WrapperSchema],
    array_strides: &BTreeMap<String, std::collections::BTreeSet<i32>>,
) {
    let mut memcpy_sites: BTreeMap<String, usize> = BTreeMap::new();
    let mut array_sites: BTreeMap<String, usize> = BTreeMap::new();
    for w in wrappers.iter_mut() {
        let strides = strides_for_wrapper(w, array_strides);
        for member in w
            .wire_order
            .iter_mut()
            .chain(w.members_from_wrapper_props.iter_mut())
        {
            let Some(elem) = collection_elem(&member.ty) else {
                continue;
            };
            let Some(payload) = unmanaged.get(&elem).map(|l| l.payload_size) else {
                continue;
            };
            *array_sites.entry(elem.clone()).or_insert(0) += 1;
            if strides.contains(&payload) {
                member.collection_encoding = Some("memcpy".into());
                *memcpy_sites.entry(elem).or_insert(0) += 1;
            }
        }
    }
    // Type-level memcpy only when every T[] / List<T> site on a wrapper that
    // owns such a field used a native memcpy reader. Mixed sites (GameplayTag
    // bornTag memcpy vs npcMontages formatter) stay field-level only.
    for (elem, total) in array_sites {
        let n = memcpy_sites.get(&elem).copied().unwrap_or(0);
        if n > 0 && n == total {
            if let Some(layout) = unmanaged.get_mut(&elem) {
                layout.collection_encoding = Some("memcpy".into());
            }
        }
    }
}

/// Nested `Beyond.Optional<T>` of a memcpy T is `ReadUnmanaged` of
/// `sizeof(Optional<T>)` only when this wrapper's Deserialize inlines that
/// many copies. Other Optional sites keep the object-header formatter.
fn apply_optional_encodings(
    unmanaged: &BTreeMap<String, UnmanagedLayout>,
    wrappers: &mut [WrapperSchema],
    struct_memcpy: &BTreeMap<String, BTreeMap<i32, usize>>,
) {
    for w in wrappers.iter_mut() {
        let counts = struct_memcpy
            .get(&w.wrapper_type)
            .cloned()
            .or_else(|| {
                w.formatter_type
                    .as_ref()
                    .and_then(|fmt| struct_memcpy.get(fmt).cloned())
            })
            .unwrap_or_default();
        if counts.is_empty() {
            continue;
        }
        let mut opt_by_payload: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
        for (i, member) in w.wire_order.iter().enumerate() {
            let Some(inner) = optional_inner(&member.ty) else {
                continue;
            };
            let Some(layout) = unmanaged
                .get(&member.ty)
                .or_else(|| unmanaged.get(&format!("Beyond.Optional`1<{inner}>")))
            else {
                continue;
            };
            if layout.status != "il2cpp_optional_unmanaged" {
                continue;
            }
            opt_by_payload
                .entry(layout.payload_size)
                .or_default()
                .push(i);
        }
        for (payload, idxs) in opt_by_payload {
            let n_copy = counts.get(&payload).copied().unwrap_or(0);
            if n_copy != idxs.len() || idxs.is_empty() {
                continue;
            }
            for i in idxs {
                w.wire_order[i].collection_encoding = Some("memcpy".into());
                if i < w.members_from_wrapper_props.len() {
                    w.members_from_wrapper_props[i].collection_encoding = Some("memcpy".into());
                }
            }
        }
    }
}

fn optional_inner(ty: &str) -> Option<String> {
    let t = ty.trim();
    const A: &str = "Beyond.Optional`1<";
    const B: &str = "Beyond.Optional<";
    for prefix in [A, B] {
        if let Some(inner) = t.strip_prefix(prefix) {
            return Some(inner.strip_suffix('>').unwrap_or(inner).trim().to_string());
        }
    }
    None
}

fn collection_elem(ty: &str) -> Option<String> {
    let t = ty.trim();
    if let Some(elem) = t.strip_suffix("[]") {
        return Some(elem.trim().to_string());
    }
    const LIST: &str = "System.Collections.Generic.List`1<";
    const SET: &str = "System.Collections.Generic.HashSet`1<";
    const OPTIONAL: &str = "Beyond.Optional`1<";
    for prefix in [LIST, SET, OPTIONAL] {
        if let Some(inner) = t.strip_prefix(prefix) {
            let inner = inner.strip_suffix('>').unwrap_or(inner).trim();
            if prefix == OPTIONAL {
                return collection_elem(inner);
            }
            return Some(inner.to_string());
        }
    }
    None
}

/// Blittable structs of three Vector3s (TrackingBounds) have a ForMemoryPack
/// object header in JsonData, not a 36-byte memcpy. Native Deserialize reads
/// header then three Vector3s; peeking memcpy bytes against wire length 3
/// collides with other unmanaged payloads.
fn apply_vector3_struct_formatters(
    unmanaged: &std::collections::BTreeMap<String, crate::layout::UnmanagedLayout>,
    wrappers: &mut [WrapperSchema],
) {
    let types: std::collections::BTreeSet<String> = unmanaged
        .iter()
        .filter(|(_, layout)| {
            layout.fields.len() >= 3 && layout.fields.iter().all(|f| f.ty == "UnityEngine.Vector3")
        })
        .map(|(name, _)| name.clone())
        .collect();
    if types.is_empty() {
        return;
    }
    for w in wrappers {
        for m in w
            .wire_order
            .iter_mut()
            .chain(w.members_from_wrapper_props.iter_mut())
        {
            if collection_elem(&m.ty).is_some() {
                continue;
            }
            if types.contains(&m.ty) {
                m.collection_encoding = Some("formatter".into());
            }
        }
    }
}

fn apply_memorypack_value_encodings(
    wrappers: &mut [WrapperSchema],
    wires: &BTreeMap<String, Vec<crate::native::MemorypackMember>>,
) {
    if wires.is_empty() {
        return;
    }
    for w in wrappers {
        let Some(tgt) = w.target_type.clone() else {
            continue;
        };
        let Some(members) = wires.get(&tgt) else {
            continue;
        };
        let mut marked = false;
        for m in w
            .wire_order
            .iter_mut()
            .chain(w.members_from_wrapper_props.iter_mut())
        {
            if m.ty == tgt {
                m.collection_encoding = Some("memorypack".into());
                marked = true;
            }
        }
        if !marked {
            continue;
        }
        w.memorypack_wire = Some(
            members
                .iter()
                .enumerate()
                .map(|(i, m)| MemberProp {
                    name: m.name.clone(),
                    raw_property: format!("memorypack:{i}"),
                    ty: m.ty.clone(),
                    property_index: i,
                    has_getter: false,
                    has_setter: true,
                    collection_encoding: m.collection_encoding.clone(),
                })
                .collect(),
        );
    }
}

fn apply_native_member_counts(wrappers: &mut [WrapperSchema], counts: &BTreeMap<String, i32>) {
    for w in wrappers {
        let n = w
            .formatter_type
            .as_ref()
            .and_then(|fmt| counts.get(fmt))
            .or_else(|| counts.get(&w.wrapper_type));
        if let Some(&n) = n {
            w.native_member_count = Some(n);
        }
    }
}

fn collect_type_names(ty: &str, out: &mut HashSet<String>) {
    out.insert(ty.to_string());
    if let Some((_, args)) = crate::wire::split_generic(ty) {
        for a in args {
            collect_type_names(&a, out);
        }
    }
    if let Some(elem) = ty.strip_suffix("[]") {
        collect_type_names(elem.trim(), out);
    }
}

fn collect_missing(
    wrappers: &[WrapperSchema],
    layouts: &TypeLayouts,
    unions: &[UnionTable],
) -> serde_json::Value {
    let mut known = HashSet::new();
    for w in wrappers {
        if let Some(t) = &w.target_type {
            known.insert(t.clone());
        }
    }
    for k in layouts.enums.keys() {
        known.insert(k.clone());
    }
    for k in layouts.unmanaged.keys() {
        known.insert(k.clone());
    }
    for u in unions {
        known.insert(u.static_type.clone());
        for v in u.tags.values() {
            known.insert(v.clone());
        }
    }
    for prim in [
        "bool", "byte", "sbyte", "short", "ushort", "int", "uint", "long", "ulong", "float",
        "double", "char", "string", "object",
    ] {
        known.insert(prim.into());
    }
    let mut missing = Vec::new();
    for w in wrappers {
        for m in &w.wire_order {
            let names = referenced_named(&m.ty);
            for n in names {
                if known.contains(&n) || crate::wire::classify(&n).label() != "named" {
                    continue;
                }
                missing.push(serde_json::json!({
                    "type": n,
                    "referenced_by": w.target_type,
                    "field": m.name,
                    "status": "unresolved",
                }));
            }
        }
    }
    serde_json::json!({
        "format": "beyond-mp-missing/1",
        "count": missing.len(),
        "note": "Types that appear on a wire but have no wrapper, enum, unmanaged layout, or union. A decoder must fail these instead of guessing.",
        "items": missing,
    })
}

fn referenced_named(ty: &str) -> Vec<String> {
    match crate::wire::classify(ty) {
        crate::wire::WireKind::Named(n) => vec![n],
        crate::wire::WireKind::List { elem } => referenced_named(&elem),
        crate::wire::WireKind::Dictionary { key, value } => {
            let mut v = referenced_named(&key);
            v.extend(referenced_named(&value));
            v
        }
        crate::wire::WireKind::Nullable { inner } => referenced_named(&inner),
        _ => Vec::new(),
    }
}

fn build_td_image_map(meta: &Metadata) -> Vec<String> {
    let mut td_image = vec![String::new(); meta.type_defs.len()];
    for img in &meta.images {
        let name = meta.image_name(img).unwrap_or_default();
        let start = img.type_start.max(0) as usize;
        let end = (start + img.type_count as usize).min(meta.type_defs.len());
        for slot in td_image.iter_mut().take(end).skip(start) {
            *slot = name.clone();
        }
    }
    td_image
}

fn method_ref(td: &TypeDefinition, idx: i32) -> i32 {
    if idx < 0 {
        return idx;
    }
    if (idx as u32) < td.method_count as u32 && td.method_index >= 0 {
        td.method_index.saturating_add(idx)
    } else {
        idx
    }
}

fn property_type_name(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    td: &TypeDefinition,
    get: i32,
    set: i32,
) -> String {
    let get = method_ref(td, get);
    let set = method_ref(td, set);
    if get >= 0 {
        if let Some(m) = meta.methods.get(get as usize) {
            return ts.name_of_index(m.return_type);
        }
    }
    if set >= 0 {
        if let Some(m) = meta.methods.get(set as usize) {
            if m.parameter_count > 0 && m.parameter_start >= 0 {
                let pidx = m.parameter_start as usize;
                if let Some(p) = meta.parameters.get(pidx) {
                    return ts.name_of_index(p.type_index);
                }
            }
        }
    }
    "object".into()
}

pub fn output_readme(counts: &Counts, unions: &[UnionTable], reg_source: &str) -> String {
    let union_n = unions.len();
    format!(
        r#"# MemoryPack Schema Export

Registration: `{reg_source}`

- Wrappers: {wrappers}
- Markers (`IMemoryPackSerialize`): {markers}
- Wire order differs from target fields: {differ}
- Formatter count: {fmt}
- Native unions: {union_n}

## Wire Order Rule

Canonical packed member order is the wrapper `__name__` property metadata order (`wire_order`), which matches native `Deserialize` setter order (often alphabetical).

**Do not** use the target type's instance field declaration order (`members_from_target_fields`).

- `wire_order` / `members_from_wrapper_props`: canonical binary order for deserialization.
- `members_from_target_fields`: instance field layout and offsets for reference only.
- `orders_differ`: true when property order diverges from field declaration order.

## Files

| File | Description |
|------|-------------|
| `protocol.{{json\|msgpack.lz4}}` | Object / collection / union / string / dictionary read operations. |
| `schemas.{{json\|msgpack.lz4}}` | One object per `*ForMemoryPack` wrapper. `wire_order` is the binary member order. |
| `enums.{{json\|msgpack.lz4}}` | Enum underlying type and width from metadata `value__`. |
| `unmanaged.{{json\|msgpack.lz4}}` | Blittable value type payloads and sizes for direct memcpy deserialization. |
| `unions.{{json\|msgpack.lz4}}` | Tag to concrete type mappings recovered from Formatter.Deserialize jumptables. |
| `union-map.{{json\|msgpack.lz4}}` | Clean tag-to-type map (`{{ static_type: {{ tag: concrete }} }}`). |
| `missing.{{json\|msgpack.lz4}}` | Referenced types with no declared rule. |
| `type_index.{{json\|msgpack.lz4}}` | Lookup index: `by_basename["X"]` and `by_type["Beyond....X"]`. |
| `type.cs` | Compact C# dump with fields ordered by `wire_order`. |
| `README.md` | This export summary. |

## Deserialization Specification

1. Read 1-byte member count header (`255` = null, `250` = wide member count followed by `int32`).
2. Read members sequentially according to `wire_order`:
   - Primitives: standard little-endian bytes.
   - Strings: default `int32` StringPool ID (`-1` empty, `-2` null), resolved via `StringPool*.byte` (inline UTF-8 only if marked `utf8` / `memorypack`).
   - Enums: width specified in `enums`.
   - List / Array: `int32` count (`-1` null) followed by elements (direct memcpy if marked in `unmanaged`).
   - Dictionary: `int32` count (`-1` null) followed by key-value pairs.
   - Nested Wrappers: recursive object header + members.
   - Polymorphic types: query `union-map` by tag for concrete wrapper.

Downstream tools (such as BydTools) own the actual MemoryPack reader and VFS decoding pipeline.
"#,
        reg_source = reg_source,
        wrappers = counts.wrappers,
        markers = counts.serialize_markers,
        differ = counts.wrappers_orders_differ_from_target_fields,
        fmt = counts.wrappers_with_formatter,
        union_n = union_n,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msgpack_lz4_roundtrip() {
        let temp = std::env::temp_dir().join("test_schema_roundtrip.msgpack.lz4");
        let sample = serde_json::json!({
            "target_type": "Beyond.Gameplay.Test",
            "wire_order": ["fieldA", "fieldB"],
            "orders_differ": false,
            "counts": 42
        });

        write_msgpack_lz4(&temp, &sample).expect("write msgpack lz4");
        let recovered: serde_json::Value = read_msgpack_lz4(&temp).expect("read msgpack lz4");
        let _ = std::fs::remove_file(&temp);

        assert_eq!(recovered, sample);
    }
}
