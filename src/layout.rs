use crate::metadata::{Metadata, TypeDefinition};
use crate::pe::PeImage;
use crate::reg::MetadataRegistration;
use crate::typesys::{field_attrs, TypeSystem};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const VALUETYPE_BIT: u32 = 1 << 0;
pub const ENUMTYPE_BIT: u32 = 1 << 1;
pub const BLITTABLE_BIT: u32 = 1 << 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumLayout {
    pub type_name: String,
    pub typedef_index: usize,
    pub underlying: String,
    pub width: u8,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmanagedField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub offset: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmanagedLayout {
    pub type_name: String,
    pub typedef_index: usize,
    pub instance_size: i32,
    pub native_size: i32,
    pub payload_size: i32,
    pub blittable: bool,
    pub fields: Vec<UnmanagedField>,
    pub status: String,
    /// Native `T[]` / `List<T>` encoding. `memcpy` = i32 count then `count * payload_size`
    /// with no per-element object header, even when T has a ForMemoryPack formatter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_encoding: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeSize {
    pub instance_size: i32,
    pub native_size: i32,
}

#[derive(Debug, Clone, Default)]
pub struct TypeLayouts {
    pub instance_size: Vec<i32>,
    pub enums: BTreeMap<String, EnumLayout>,
    pub unmanaged: BTreeMap<String, UnmanagedLayout>,
}

impl TypeLayouts {
    pub fn enum_width(&self, type_name: &str) -> Option<u8> {
        self.enums.get(type_name).map(|e| e.width)
    }
}

pub fn is_valuetype(td: &TypeDefinition) -> bool {
    td.bitfield & VALUETYPE_BIT != 0
}

pub fn is_enumtype(td: &TypeDefinition) -> bool {
    td.bitfield & ENUMTYPE_BIT != 0
}

pub fn is_blittable(td: &TypeDefinition) -> bool {
    td.bitfield & BLITTABLE_BIT != 0
}

/// `Il2CppTypeDefinitionSizes**` — pointer table, same shape as `fieldOffsets`.
pub fn load_type_sizes(pe: &PeImage, reg: &MetadataRegistration) -> Vec<TypeSize> {
    let n = reg.type_definitions_sizes_count as usize;
    let mut out = vec![TypeSize::default(); n];
    if reg.type_definitions_sizes == 0 {
        return out;
    }
    if let Some(ptrs) = pe.read_u64_array_va(reg.type_definitions_sizes, n) {
        let mut hits = 0usize;
        for (i, ptr) in ptrs.into_iter().enumerate() {
            if ptr == 0 || !pe.va_mapped(ptr) {
                continue;
            }
            let Some(instance_size) = pe.read_i32_va(ptr) else {
                continue;
            };
            let native_size = pe.read_i32_va(ptr + 4).unwrap_or(-1);
            out[i] = TypeSize {
                instance_size,
                native_size,
            };
            if instance_size > 0 {
                hits += 1;
            }
        }
        if hits > 0 {
            return out;
        }
    }
    // Packed 16-byte structs (synthetic images / unexpected IL2CPP).
    for (i, slot) in out.iter_mut().enumerate() {
        let Some(sz) = pe.read_i32_va(reg.type_definitions_sizes + (i as u64) * 16) else {
            break;
        };
        slot.instance_size = sz;
        slot.native_size = pe
            .read_i32_va(reg.type_definitions_sizes + (i as u64) * 16 + 4)
            .unwrap_or(-1);
    }
    out
}

pub fn load_instance_sizes(pe: &PeImage, reg: &MetadataRegistration) -> Vec<i32> {
    load_type_sizes(pe, reg)
        .into_iter()
        .map(|s| s.instance_size)
        .collect()
}

pub fn collect_layouts(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    field_offs: &HashMap<(usize, usize), i32>,
    type_sizes: &[TypeSize],
    referenced: &HashSet<String>,
) -> TypeLayouts {
    let mut enums = BTreeMap::new();
    for (ti, td) in meta.type_defs.iter().enumerate() {
        if !is_enumtype(td) {
            continue;
        }
        let name = ts.typedef_full_name(ti as i32);
        if let Some(layout) = enum_layout(meta, ts, ti, td, &name) {
            enums.insert(name, layout);
        }
    }

    let mut unmanaged = BTreeMap::new();
    let mut memcpy_ok = vec![false; meta.type_defs.len()];
    for (ti, td) in meta.type_defs.iter().enumerate() {
        memcpy_ok[ti] = is_enumtype(td) || valuetype_is_memcpy(meta, ts, ti, td);
    }
    // Nested valuetypes (AnimationClipAsyncInfo.averageSpeed: Vector3).
    for _ in 0..8 {
        let mut changed = false;
        for (ti, td) in meta.type_defs.iter().enumerate() {
            if memcpy_ok[ti] || !is_valuetype(td) || is_enumtype(td) {
                continue;
            }
            if valuetype_fields_are_memcpy(meta, ts, ti, td, &memcpy_ok) {
                memcpy_ok[ti] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for (ti, td) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        if is_enumtype(td) || !is_valuetype(td) {
            continue;
        }
        if !referenced.contains(&name) && !is_unity_packed(&name) {
            continue;
        }
        // native_size > 0 is not enough: valuetypes that hold a string/object
        // pointer still have a native size (the pointer width). Only emit
        // types whose instance fields are primitives, enums, or nested memcpy.
        if !memcpy_ok[ti] && !is_unity_packed(&name) {
            continue;
        }
        if let Some(layout) = unmanaged_layout(
            meta, ts, field_offs, type_sizes, &enums, &memcpy_ok, ti, td, &name,
        ) {
            unmanaged.insert(name, layout);
        }
    }

    emit_closed_generic_unmanaged(&mut unmanaged, &enums, referenced);

    TypeLayouts {
        instance_size: type_sizes.iter().map(|s| s.instance_size).collect(),
        enums,
        unmanaged,
    }
}

fn enum_layout(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    ti: usize,
    td: &TypeDefinition,
    name: &str,
) -> Option<EnumLayout> {
    if td.field_count == 0 || td.field_index < 0 {
        return None;
    }
    let start = td.field_index as usize;
    for fi in start..start + td.field_count as usize {
        let f = meta.fields.get(fi)?;
        let fname = meta.string(f.name_index).ok()?;
        if fname != "value__" {
            continue;
        }
        let underlying = ts.name_of_index(f.type_index);
        let width = primitive_width(&underlying)?;
        return Some(EnumLayout {
            type_name: name.to_string(),
            typedef_index: ti,
            underlying,
            width,
            status: "metadata_value__".into(),
        });
    }
    None
}

fn valuetype_is_memcpy(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    ti: usize,
    td: &TypeDefinition,
) -> bool {
    valuetype_fields_are_memcpy(meta, ts, ti, td, &[])
}

fn valuetype_fields_are_memcpy(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    ti: usize,
    td: &TypeDefinition,
    nested_ok: &[bool],
) -> bool {
    if !is_valuetype(td) || is_enumtype(td) {
        return false;
    }
    let mut n = 0;
    for field in instance_fields(meta, ts, ti, td, &HashMap::new()) {
        if primitive_width(&field.ty).is_some() || is_unity_packed(&field.ty) {
            n += 1;
            continue;
        }
        let Some(field_tdi) = ts.typedef_index_of(field.type_index) else {
            return false;
        };
        let Some(field_td) = meta.type_defs.get(field_tdi as usize) else {
            return false;
        };
        if is_enumtype(field_td) {
            n += 1;
            continue;
        }
        let idx = field_tdi as usize;
        if idx < nested_ok.len() && nested_ok[idx] {
            n += 1;
            continue;
        }
        return false;
    }
    n > 0
}

struct InstanceField {
    name: String,
    ty: String,
    type_index: i32,
    offset: i32,
}

fn instance_fields(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    ti: usize,
    td: &TypeDefinition,
    field_offs: &HashMap<(usize, usize), i32>,
) -> Vec<InstanceField> {
    let mut out = Vec::new();
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
        out.push(InstanceField {
            name: meta.string(f.name_index).unwrap_or_else(|_| "?".into()),
            ty: ts.name_of_index(f.type_index),
            type_index: f.type_index,
            offset: field_offs.get(&(ti, local)).copied().unwrap_or(0),
        });
    }
    out
}

fn field_payload_size(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    enums: &BTreeMap<String, EnumLayout>,
    type_sizes: &[TypeSize],
    field: &InstanceField,
) -> Option<i32> {
    if let Some(w) = primitive_width(&field.ty) {
        return Some(w as i32);
    }
    if let Some(n) = unity_packed_size(&field.ty) {
        return Some(n);
    }
    if let Some(e) = enums.get(&field.ty) {
        return Some(e.width as i32);
    }
    let tdi = ts.typedef_index_of(field.type_index)? as usize;
    if meta.type_defs.get(tdi).is_some_and(is_enumtype) {
        if let Some(e) = enums.values().find(|e| e.typedef_index == tdi) {
            return Some(e.width as i32);
        }
    }
    let native = type_sizes.get(tdi).map(|s| s.native_size).unwrap_or(-1);
    if native > 0 {
        return Some(native);
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn unmanaged_layout(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    field_offs: &HashMap<(usize, usize), i32>,
    type_sizes: &[TypeSize],
    enums: &BTreeMap<String, EnumLayout>,
    _memcpy_ok: &[bool],
    ti: usize,
    td: &TypeDefinition,
    name: &str,
) -> Option<UnmanagedLayout> {
    let sizes = type_sizes.get(ti).copied().unwrap_or_default();
    let raw = instance_fields(meta, ts, ti, td, field_offs);
    let mut fields = Vec::new();
    for field in &raw {
        fields.push(UnmanagedField {
            size: field_payload_size(meta, ts, enums, type_sizes, field),
            name: field.name.clone(),
            ty: field.ty.clone(),
            offset: field.offset,
        });
    }
    if fields.is_empty() && sizes.native_size <= 0 {
        return None;
    }
    let min_off = fields.iter().map(|f| f.offset).min().unwrap_or(0);
    let boxed = min_off >= 16;
    if boxed {
        for f in &mut fields {
            f.offset -= 16;
        }
    }
    let mut end = 0i32;
    for f in &fields {
        let sz = f.size.unwrap_or(0);
        end = end.max(f.offset + sz);
    }
    let payload = memcpy_payload_size(end, sizes.native_size, sizes.instance_size, boxed);
    if payload <= 0 {
        return None;
    }
    Some(UnmanagedLayout {
        type_name: name.to_string(),
        typedef_index: ti,
        instance_size: sizes.instance_size,
        native_size: sizes.native_size,
        payload_size: payload,
        blittable: is_blittable(td),
        fields,
        status: "il2cpp_native_valuetype".into(),
        collection_encoding: None,
    })
}

fn align4(n: i32) -> i32 {
    if n <= 0 {
        0
    } else {
        (n + 3) & !3
    }
}

/// MemoryPack `WriteUnmanaged` memcpy width.
///
/// Boxed valuetypes (`min_off >= 16`) copy `instance_size - 16` bytes. That
/// includes ABI trailing padding after the last field (`LevelScriptPtr`:
/// ulong+int packed 12, boxed payload 16) and is the width NPC montage
/// actually writes for `AnimationClipAsyncInfo` (36, not `native_size` 40).
/// Unboxed layouts fall back to `native_size` when it is larger than the
/// packed span. Packed span is a lower bound in every case.
/// `Nullable<T>` unboxed size: `hasValue` at 0, `value` at `align(T)`, then
/// ABI pad to `align(T)`. Boxed payload is that native size (`Nullable<float>`
/// native 8, GameAssembly `cmp remaining, 8` then `mov qword`).
/// Nested `Beyond.Optional<T>` wire width is the unboxed struct: `enabled` at 0,
/// `value` at `align(T)`, then pad to `align(T)`. No extra 4-byte ABI bump —
/// native `Optional<bool>` is 2 bytes (`mov edx, 2` in InteractiveTemplateVariant).
fn optional_memcpy_payload(inner_size: i32, inner_align: i32) -> i32 {
    let align = inner_align.max(1);
    let value_off = align_n(1, align);
    let packed = value_off + inner_size;
    align_n(packed, align)
}

fn nullable_memcpy_payload(inner_size: i32, inner_align: i32) -> i32 {
    let align = inner_align.max(1);
    let value_off = align_n(1, align);
    let packed = value_off + inner_size;
    let native = align_n(packed, align);
    memcpy_payload_size(packed, native, 16 + native, true)
}

fn align_n(n: i32, align: i32) -> i32 {
    if n <= 0 {
        0
    } else if align <= 1 {
        n
    } else {
        (n + align - 1) / align * align
    }
}

fn emit_closed_generic_unmanaged(
    unmanaged: &mut BTreeMap<String, UnmanagedLayout>,
    enums: &BTreeMap<String, EnumLayout>,
    referenced: &HashSet<String>,
) {
    let names: Vec<String> = referenced.iter().cloned().collect();
    for name in names {
        if unmanaged.contains_key(&name) {
            continue;
        }
        let Some((head, args)) = crate::wire::split_generic(&name) else {
            continue;
        };
        let leaf = head.rsplit('.').next().unwrap_or(head);
        if leaf.starts_with("ValueTuple`") {
            if let Some(layout) = value_tuple_layout(&name, &args, enums, unmanaged) {
                unmanaged.insert(name.clone(), layout);
            }
            continue;
        }
        if args.len() != 1 {
            continue;
        }
        let (flag_name, status) = if leaf.starts_with("Nullable`") {
            ("hasValue", "il2cpp_nullable_unmanaged")
        } else if leaf.starts_with("Optional`") {
            // Nested Beyond.Optional<T> of a memcpy T is ReadUnmanaged of
            // sizeof(Optional<T>), not the Optional ForMemoryPack object header.
            // Evidence: InteractiveTemplateVariant.cctor after cmp memberCount
            // 14: 8-byte Optional<enum>/float, later 2-byte Optional<bool>.
            ("enabled", "il2cpp_optional_unmanaged")
        } else {
            continue;
        };
        let inner = &args[0];
        let Some((inner_size, inner_align)) = inner_memcpy_size_align(inner, enums, unmanaged)
        else {
            continue;
        };
        let payload = if status.starts_with("il2cpp_optional") {
            optional_memcpy_payload(inner_size, inner_align)
        } else {
            nullable_memcpy_payload(inner_size, inner_align)
        };
        if payload <= 0 {
            continue;
        }
        let value_off = align_n(1, inner_align.max(1));
        unmanaged.insert(
            name.clone(),
            UnmanagedLayout {
                type_name: name,
                typedef_index: 0,
                instance_size: 16 + payload,
                native_size: payload,
                payload_size: payload,
                blittable: true,
                fields: vec![
                    UnmanagedField {
                        name: flag_name.into(),
                        ty: "bool".into(),
                        offset: 0,
                        size: Some(1),
                    },
                    UnmanagedField {
                        name: "value".into(),
                        ty: inner.clone(),
                        offset: value_off,
                        size: Some(inner_size),
                    },
                ],
                status: status.into(),
                collection_encoding: None,
            },
        );
    }
}

/// Closed `ValueTuple<T…>` of memcpy args is sequential unmanaged items.
/// `List<ValueTuple<Vector3, Vector3>>` on SpaceShipSpecificData is i32 count
/// then `count * 24` with no per-element object header.
fn value_tuple_layout(
    name: &str,
    args: &[String],
    enums: &BTreeMap<String, EnumLayout>,
    unmanaged: &BTreeMap<String, UnmanagedLayout>,
) -> Option<UnmanagedLayout> {
    if args.is_empty() || args.len() > 8 {
        return None;
    }
    let mut fields = Vec::new();
    let mut offset = 0i32;
    let mut max_align = 1i32;
    for (i, arg) in args.iter().enumerate() {
        let (size, align) = inner_memcpy_size_align(arg, enums, unmanaged)?;
        let align = align.max(1);
        offset = align_n(offset, align);
        fields.push(UnmanagedField {
            name: format!("Item{}", i + 1),
            ty: arg.clone(),
            offset,
            size: Some(size),
        });
        offset += size;
        max_align = max_align.max(align);
    }
    let payload = align_n(offset, max_align);
    if payload <= 0 {
        return None;
    }
    Some(UnmanagedLayout {
        type_name: name.to_string(),
        typedef_index: 0,
        instance_size: 16 + payload,
        native_size: payload,
        payload_size: payload,
        blittable: true,
        fields,
        status: "il2cpp_valuetuple_unmanaged".into(),
        collection_encoding: None,
    })
}

fn inner_memcpy_size_align(
    name: &str,
    enums: &BTreeMap<String, EnumLayout>,
    unmanaged: &BTreeMap<String, UnmanagedLayout>,
) -> Option<(i32, i32)> {
    if let Some(w) = primitive_width(name) {
        return Some((w as i32, w as i32));
    }
    if let Some(sz) = unity_packed_size(name) {
        let align = if is_unity_packed(name) {
            4.min(sz).max(1)
        } else {
            4
        };
        return Some((sz, align));
    }
    if let Some(e) = enums.get(name) {
        let w = e.width as i32;
        return Some((w, w.max(1)));
    }
    let layout = unmanaged.get(name)?;
    let align = layout
        .fields
        .iter()
        .filter_map(|f| {
            primitive_width(&f.ty)
                .map(|w| w as i32)
                .or_else(|| enums.get(&f.ty).map(|e| e.width as i32))
        })
        .max()
        .unwrap_or(4)
        .max(1);
    Some((layout.payload_size, align))
}

fn memcpy_payload_size(packed_end: i32, native_size: i32, instance_size: i32, boxed: bool) -> i32 {
    let mut payload = align4(packed_end);
    if boxed && instance_size > 16 {
        payload = payload.max(instance_size - 16);
    } else if native_size > payload {
        payload = native_size;
    }
    if payload <= 0 && native_size > 0 {
        payload = native_size;
    }
    payload
}

fn unity_packed_size(name: &str) -> Option<i32> {
    match name {
        "UnityEngine.Vector2" | "UnityEngine.Vector2Int" => Some(8),
        "UnityEngine.Vector3" | "UnityEngine.Vector3Int" => Some(12),
        "UnityEngine.Vector4" | "UnityEngine.Quaternion" | "UnityEngine.Color" => Some(16),
        "UnityEngine.Color32" => Some(4),
        _ => None,
    }
}

pub fn primitive_width(ty: &str) -> Option<u8> {
    match ty {
        "bool" | "System.Boolean" | "sbyte" | "System.SByte" | "byte" | "System.Byte" => Some(1),
        "short" | "System.Int16" | "ushort" | "System.UInt16" | "char" | "System.Char" => Some(2),
        "int" | "System.Int32" | "uint" | "System.UInt32" | "float" | "System.Single" => Some(4),
        "long" | "System.Int64" | "ulong" | "System.UInt64" | "double" | "System.Double" => Some(8),
        _ => None,
    }
}

fn is_unity_packed(name: &str) -> bool {
    matches!(
        name,
        "UnityEngine.Vector2"
            | "UnityEngine.Vector3"
            | "UnityEngine.Vector4"
            | "UnityEngine.Quaternion"
            | "UnityEngine.Color"
            | "UnityEngine.Color32"
            | "UnityEngine.Vector2Int"
            | "UnityEngine.Vector3Int"
    )
}

pub fn skip_parent_name(name: &str) -> bool {
    matches!(
        name,
        "object"
            | "System.Object"
            | "ValueType"
            | "System.ValueType"
            | "Enum"
            | "System.Enum"
            | "System.MulticastDelegate"
            | "System.Delegate"
    )
}

#[cfg(test)]
mod tests {
    use super::{memcpy_payload_size, nullable_memcpy_payload, optional_memcpy_payload};

    #[test]
    fn level_script_ptr_uses_boxed_padding() {
        assert_eq!(memcpy_payload_size(12, 16, 32, true), 16);
    }

    #[test]
    fn animation_clip_async_info_keeps_boxed_36_not_native_40() {
        assert_eq!(memcpy_payload_size(34, 40, 52, true), 36);
    }

    #[test]
    fn packed_span_wins_when_native_is_smaller() {
        assert_eq!(memcpy_payload_size(8, 4, 24, false), 8);
    }

    #[test]
    fn equal_native_and_packed_is_unchanged() {
        assert_eq!(memcpy_payload_size(16, 16, 32, true), 16);
    }

    #[test]
    fn nullable_float_memcpy_is_8() {
        assert_eq!(nullable_memcpy_payload(4, 4), 8);
    }

    #[test]
    fn nullable_ulong_memcpy_is_16() {
        assert_eq!(nullable_memcpy_payload(8, 8), 16);
    }

    #[test]
    fn optional_bool_memcpy_is_2() {
        assert_eq!(optional_memcpy_payload(1, 1), 2);
    }

    #[test]
    fn optional_float_memcpy_is_8() {
        assert_eq!(optional_memcpy_payload(4, 4), 8);
    }

    #[test]
    fn optional_vector3_memcpy_is_16() {
        assert_eq!(optional_memcpy_payload(12, 4), 16);
    }

    #[test]
    fn value_tuple_two_vector3_is_24() {
        use super::{inner_memcpy_size_align, value_tuple_layout};
        use std::collections::BTreeMap;
        let unmanaged = BTreeMap::new();
        let enums = BTreeMap::new();
        let args = ["UnityEngine.Vector3".into(), "UnityEngine.Vector3".into()];
        let layout = value_tuple_layout(
            "System.ValueTuple`2<UnityEngine.Vector3, UnityEngine.Vector3>",
            &args,
            &enums,
            &unmanaged,
        )
        .expect("tuple");
        assert_eq!(layout.payload_size, 24);
        assert_eq!(layout.fields[0].offset, 0);
        assert_eq!(layout.fields[1].offset, 12);
        assert_eq!(
            inner_memcpy_size_align("UnityEngine.Vector3", &enums, &unmanaged),
            Some((12, 4))
        );
    }
}
