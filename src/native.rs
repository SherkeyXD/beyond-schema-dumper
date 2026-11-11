use crate::codegen::CodeMap;
use crate::metadata::Metadata;
use crate::pe::PeImage;
use crate::typesys::TypeSystem;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionTag {
    pub tag: i32,
    pub type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapper_type: Option<String>,
    pub typedef_index: usize,
    pub case_va: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionTable {
    pub static_type: String,
    pub wrapper_type: String,
    pub formatter_type: String,
    pub deserialize_va: String,
    pub max_tag: i32,
    pub jumptable_rva: String,
    pub tags: BTreeMap<String, String>,
    pub evidence: Vec<UnionTag>,
    pub skipped: Vec<i32>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NativeFacts {
    pub unions: Vec<UnionTable>,
    pub member_counts: BTreeMap<String, i32>,
    /// Wrapper type → native `T[]` memcpy strides recovered from callees.
    pub array_strides: BTreeMap<String, BTreeSet<i32>>,
    /// Wrapper type → count of inline `add [reader+0x50], N` unmanaged copies
    /// (`N` in 2/8/16). Nested `Optional<T>` of a memcpy T uses this, not an
    /// object header.
    pub struct_memcpy: BTreeMap<String, BTreeMap<i32, usize>>,
    /// Target type → members of the nested `T+TFormatter` MemoryPack formatter.
    /// Used when a wrapper field is `ReadValue<T>` (self-typed extra) instead of
    /// the Beyond StringPool wrapper wire.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub memorypack_wires: BTreeMap<String, Vec<MemorypackMember>>,
    /// Parent ForMemoryPack declaring name → unmanaged targets whose
    /// `*ForMemoryPack.Deserialize` is called from that parent. Evidence only:
    /// auto-marking those scalars as `formatter` false-positives
    /// `WeaponMountTargetDesc`. TrackingBounds uses the Vector3-struct rule.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nested_formatters: BTreeMap<String, BTreeSet<String>>,
}

/// One member of a nested MemoryPack `TFormatter` (UTF-8 strings, not StringPool).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorypackMember {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_encoding: Option<String>,
}

struct PdataFn {
    begin_rva: u32,
    end_rva: u32,
}

/// IL2CPP cold-split entries are a short thunk. Larger `.pdata` already
/// covers the Deserialize body, including the jumptable.
const COLD_ENTRY_MAX: u64 = 0x100;

pub fn analyze(
    pe: &PeImage,
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    code: &CodeMap,
    wrapper_by_target_td: &BTreeMap<usize, String>,
    target_name_by_td: &BTreeMap<usize, String>,
    target_name_by_wrapper_td: &BTreeMap<usize, String>,
) -> NativeFacts {
    let pdata = load_pdata(pe);
    let mut facts = NativeFacts::default();
    let mut seen_va = HashSet::new();
    let mut by_table: BTreeMap<String, UnionTable> = BTreeMap::new();

    for method in &code.methods {
        if !is_union_candidate(method) {
            continue;
        }
        if !seen_va.insert(method.va) {
            continue;
        }
        let mut best: Option<UnionTable> = None;
        for (begin, end) in method_windows(pe, &pdata, method.va) {
            let size = end.saturating_sub(begin) as usize;
            if size < 24 {
                continue;
            }
            let Some(bytes) = pe.slice_va(begin, size) else {
                continue;
            };
            if let Some(n) = find_inline_member_count(bytes) {
                facts
                    .member_counts
                    .entry(method.declaring_name.clone())
                    .and_modify(|cur| *cur = (*cur).max(n))
                    .or_insert(n);
            }
            record_array_strides(pe, &mut facts, &method.declaring_name, begin, bytes);
            record_struct_memcpy(pe, &mut facts, &method.declaring_name, begin, bytes);
            for (max_tag, table_rva) in find_jumptables_in_bytes(bytes) {
                if !jumptable_is_code(pe, table_rva, max_tag) {
                    continue;
                }
                let Some(union) = build_union(
                    pe,
                    meta,
                    ts,
                    max_tag,
                    table_rva,
                    method,
                    wrapper_by_target_td,
                    target_name_by_td,
                    target_name_by_wrapper_td,
                ) else {
                    continue;
                };
                if !union_is_plausible(&union) {
                    continue;
                }
                best = Some(better_union(best, union));
            }
            // SpawnerActionData: `cmp tag, N; jne cold` then cold is
            // `ja fail; jumptable` for 0..N-1. Fallthrough is tag N.
            for (imm, target, fallthrough) in find_cmp_jne_targets(bytes, begin) {
                let Some(cold) = pe.slice_va(target, 96) else {
                    continue;
                };
                let Some(table_rva) = find_ja_jumptable(cold) else {
                    continue;
                };
                let table_max = imm - 1;
                if table_max < 1 || !jumptable_is_code(pe, table_rva, table_max) {
                    continue;
                }
                let Some(mut union) = build_union(
                    pe,
                    meta,
                    ts,
                    table_max,
                    table_rva,
                    method,
                    wrapper_by_target_td,
                    target_name_by_td,
                    target_name_by_wrapper_td,
                ) else {
                    continue;
                };
                if let Some((type_name, wrapper, td)) = resolve_union_case(
                    pe,
                    ts,
                    fallthrough,
                    wrapper_by_target_td,
                    target_name_by_td,
                    target_name_by_wrapper_td,
                ) {
                    union.tags.insert(imm.to_string(), type_name.clone());
                    union.max_tag = union.max_tag.max(imm);
                    union.evidence.push(UnionTag {
                        tag: imm,
                        type_name,
                        wrapper_type: wrapper,
                        typedef_index: td,
                        case_va: format!("{fallthrough:#x}"),
                    });
                    union.status = "native_split_jumptable".into();
                }
                if !union_is_plausible(&union) {
                    continue;
                }
                best = Some(better_union(best, union));
            }
            for cases in find_ifeq_tag_groups(Some(pe), begin, bytes) {
                let Some(union) = build_union_from_cases(
                    pe,
                    meta,
                    ts,
                    &cases,
                    method,
                    wrapper_by_target_td,
                    target_name_by_td,
                    target_name_by_wrapper_td,
                ) else {
                    continue;
                };
                if !union_is_plausible(&union) {
                    continue;
                }
                best = Some(better_union(best, union));
            }
        }
        // Short `.pdata` often ends before the Deserialize body (FAnimationCurve
        // `.cctor` is 0x5b bytes; the FKeyframe[] call is at +0x93). GameplayTag[]
        // memcpy callees sit similarly far into InteractiveTemplateData.
        // Always scan a long prefix for memcpy-array callees.
        if let Some(prefix) = pe.slice_va(method.va, 4096) {
            record_array_strides(pe, &mut facts, &method.declaring_name, method.va, prefix);
            record_struct_memcpy(pe, &mut facts, &method.declaring_name, method.va, prefix);
        }
        if let Some(union) = best {
            merge_by_jumptable(&mut by_table, union);
        }
    }
    facts.unions = merge_by_static_type(by_table.into_values().collect());
    facts
        .unions
        .sort_by(|a, b| a.static_type.cmp(&b.static_type));
    facts.memorypack_wires = recover_memorypack_wires(pe, meta, ts, code);
    facts.nested_formatters =
        recover_nested_formatters(pe, meta, ts, code, target_name_by_wrapper_td);
    facts
}

/// Nested `SendLuaEvent1+SendLuaEvent1Formatter` (not Beyond ForMemoryPack) is
/// MemoryPack's generated formatter. `ReadValue<T>` uses it: object header then
/// UTF-8 strings / ReadUnmanaged / GetFormatter&lt;Param&gt; (Beyond Param still
/// uses the StringPool formatter). Evidence: indie_race001 header `07` then
/// int, UTF-8 `"21afb3dd"`, bool, null string, bool, Param&lt;string&gt;, UTF-8 JSON.
fn recover_memorypack_wires(
    pe: &PeImage,
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    code: &CodeMap,
) -> BTreeMap<String, Vec<MemorypackMember>> {
    let mut by_va: BTreeMap<u64, &crate::codegen::MethodVa> = BTreeMap::new();
    let mut reader: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for m in &code.methods {
        by_va.insert(m.va, m);
        if m.declaring_name.ends_with("MemoryPackReader")
            || m.declaring_name.ends_with("MemoryPackFormatterProvider")
        {
            reader.entry(m.name.clone()).or_default().push(m.va);
        }
    }
    let named = MpNamedVas {
        header: named_reader_vas(&reader, &["TryReadObjectHeader", "ReadObjectHeader"]),
        int: named_reader_vas(&reader, &["ReadInt32", "ReadUInt32"]),
        bools: named_reader_vas(&reader, &["ReadByte", "ReadBoolean"]),
        string: expand_string_helpers(pe, &named_reader_vas(&reader, &["ReadString"])),
        value: named_reader_vas(&reader, &["ReadValue", "GetFormatter"]),
    };

    let mut parent_of_formatter: BTreeMap<String, String> = BTreeMap::new();
    for (ti, _) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        let Some((parent, leaf)) = name.rsplit_once('+') else {
            continue;
        };
        if leaf.contains("ForMemoryPack") {
            continue;
        }
        let parent_leaf = parent.rsplit(['.', '+']).next().unwrap_or(parent);
        if leaf != format!("{parent_leaf}Formatter") {
            continue;
        }
        parent_of_formatter.insert(leaf.to_string(), parent.to_string());
        parent_of_formatter.insert(name.clone(), parent.to_string());
        if let Some((_, short)) = parent.rsplit_once('.') {
            parent_of_formatter.insert(format!("{short}+{leaf}"), parent.to_string());
        }
    }

    let mut out: BTreeMap<String, Vec<MemorypackMember>> = BTreeMap::new();
    for m in &code.methods {
        let Some(target) = parent_of_formatter.get(&m.declaring_name) else {
            continue;
        };
        if m.name != "Deserialize" && m.name != "Register" && m.name != ".cctor" {
            continue;
        }
        let Some(bytes) = pe.slice_va(m.va, 2048) else {
            continue;
        };
        let calls = find_rel32_calls(m.va, bytes);
        let mut kinds: Vec<MpRead> = Vec::new();
        let mut seen_header = false;
        let mut gap = 0usize;
        for &c in &calls {
            if by_va.get(&c).map(|x| x.name.as_str()) == Some(".ctor") {
                continue;
            }
            match classify_mp_callee(pe, c, &named) {
                Some(MpClass::Header) => {
                    if seen_header && !kinds.is_empty() {
                        break;
                    }
                    seen_header = true;
                    gap = 0;
                }
                Some(kind) if seen_header => {
                    kinds.push(match kind {
                        MpClass::Int => MpRead::Int,
                        MpClass::Bool => MpRead::Bool,
                        MpClass::Utf8 => MpRead::Utf8,
                        MpClass::Value => MpRead::Value,
                        MpClass::Header => unreachable!(),
                    });
                    gap = 0;
                }
                Some(_) => {}
                None => {
                    if seen_header && !kinds.is_empty() {
                        gap += 1;
                        if gap >= 2 {
                            break;
                        }
                    }
                }
            }
            if kinds.len() >= 12 {
                break;
            }
        }
        // Inlined MemoryPack.ReadString of a null is just ReadInt32(-1).
        // Pattern int, utf8, bool, int, bool → that second int is a string.
        if kinds.len() >= 5
            && matches!(
                &kinds[..5],
                [
                    MpRead::Int,
                    MpRead::Utf8,
                    MpRead::Bool,
                    MpRead::Int,
                    MpRead::Bool
                ]
            )
        {
            kinds[3] = MpRead::Utf8;
        }
        if !seen_header || kinds.len() < 3 {
            continue;
        }
        let members = memorypack_members_from_reads(target, meta, ts, &kinds);
        let entry = out.entry(target.clone()).or_default();
        if members.len() > entry.len() {
            *entry = members;
        }
    }
    out
}

struct MpNamedVas {
    header: BTreeSet<u64>,
    int: BTreeSet<u64>,
    bools: BTreeSet<u64>,
    string: BTreeSet<u64>,
    value: BTreeSet<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MpClass {
    Header,
    Int,
    Bool,
    Utf8,
    Value,
}

/// Parent wrapper/formatter Deserialize calling another `*ForMemoryPack.Deserialize`
/// means that nested valuetype is the object-header formatter, not memcpy.
fn recover_nested_formatters(
    pe: &PeImage,
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    code: &CodeMap,
    target_name_by_wrapper_td: &BTreeMap<usize, String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut declaring_to_target: BTreeMap<String, String> = BTreeMap::new();
    for (&wrapper_td, target) in target_name_by_wrapper_td {
        if wrapper_td >= meta.type_defs.len() {
            continue;
        }
        let td = &meta.type_defs[wrapper_td];
        if let Ok(name) = meta.type_name(td) {
            declaring_to_target.insert(name, target.clone());
        }
        declaring_to_target.insert(ts.typedef_full_name(wrapper_td as i32), target.clone());
        for child in meta.nested_children(td) {
            let ctd = &meta.type_defs[child];
            if let Ok(name) = meta.type_name(ctd) {
                declaring_to_target.insert(name, target.clone());
            }
            declaring_to_target.insert(ts.typedef_full_name(child as i32), target.clone());
        }
    }
    let mut by_va: BTreeMap<u64, &crate::codegen::MethodVa> = BTreeMap::new();
    for m in &code.methods {
        by_va.insert(m.va, m);
    }
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for m in &code.methods {
        if m.name != "Deserialize" && m.name != ".cctor" {
            continue;
        }
        if !m.declaring_name.contains("ForMemoryPack") {
            continue;
        }
        let parent_target = declaring_to_target.get(&m.declaring_name);
        let Some(bytes) = pe.slice_va(m.va, 2048) else {
            continue;
        };
        for c in find_rel32_calls(m.va, bytes) {
            let resolved = follow_jmps(pe, c, 6);
            let Some(callee) = by_va.get(&c).or_else(|| by_va.get(&resolved)) else {
                continue;
            };
            if callee.name != "Deserialize" {
                continue;
            }
            let Some(tgt) = declaring_to_target.get(&callee.declaring_name) else {
                continue;
            };
            if parent_target == Some(tgt) {
                continue;
            }
            out.entry(m.declaring_name.clone())
                .or_default()
                .insert(tgt.clone());
        }
    }
    out
}

fn named_reader_vas(reader: &BTreeMap<String, Vec<u64>>, names: &[&str]) -> BTreeSet<u64> {
    names
        .iter()
        .filter_map(|n| reader.get(*n))
        .flatten()
        .copied()
        .collect()
}

/// ReadString thunks call the collection-header helper (`cmp remaining, 4` +
/// store length to an out-pointer). Public `ReadString` is a different VA.
fn expand_string_helpers(pe: &PeImage, string_vas: &BTreeSet<u64>) -> BTreeSet<u64> {
    let mut out = string_vas.clone();
    for &va in string_vas {
        let Some(bytes) = pe.slice_va(va, 96) else {
            continue;
        };
        for c in find_rel32_calls(va, bytes) {
            let Some(body) = pe.slice_va(c, 80) else {
                continue;
            };
            if remaining_imm(body) == Some(4) && stores_length_out(body) {
                out.insert(c);
            }
        }
    }
    out
}

/// IL2CPP MemoryPack formatters call tiny remaining-count helpers that are
/// not the public `MemoryPackReader.ReadInt32` / `TryReadObjectHeader` VAs.
fn classify_mp_callee(pe: &PeImage, va: u64, named: &MpNamedVas) -> Option<MpClass> {
    if named.bools.contains(&va) {
        return Some(MpClass::Bool);
    }
    if named.header.contains(&va) {
        return Some(MpClass::Header);
    }
    if named.string.contains(&va) || call_thunks_to(pe, va, &named.string) {
        return Some(MpClass::Utf8);
    }
    if named.int.contains(&va) || call_thunks_to(pe, va, &named.int) {
        return Some(MpClass::Int);
    }
    if named.value.contains(&va) || call_thunks_to(pe, va, &named.value) {
        return Some(MpClass::Value);
    }
    let bytes = pe.slice_va(va, 80)?;
    if remaining_imm(bytes) == Some(1) && has_cmp_imm8_ff(bytes) {
        return Some(MpClass::Header);
    }
    if remaining_imm(bytes) == Some(4) && !stores_length_out(bytes) {
        return Some(MpClass::Int);
    }
    if looks_like_get_formatter(bytes) {
        return Some(MpClass::Value);
    }
    None
}

/// `cmp dword [r+0x30], imm8` — MemoryPackReader remaining-byte check.
fn remaining_imm(bytes: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if bytes[i] == 0x83 && bytes[i + 2] == 0x30 && bytes[i + 1] & 0xF8 == 0x78 {
            return Some(bytes[i + 3]);
        }
        if i + 4 < bytes.len()
            && bytes[i] == 0x41
            && bytes[i + 1] == 0x83
            && bytes[i + 3] == 0x30
            && bytes[i + 2] & 0xF8 == 0x78
        {
            return Some(bytes[i + 4]);
        }
        i += 1;
    }
    None
}

fn has_cmp_imm8_ff(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|w| w[0] == 0x80 && w[2] == 0xFF)
        || bytes
            .windows(4)
            .any(|w| w[0] == 0x40 && w[1] == 0x80 && w[3] == 0xFF)
}

fn stores_length_out(bytes: &[u8]) -> bool {
    // `mov [rdi], ecx` / `mov [rdx], eax` — TryReadCollectionHeader out-param.
    bytes
        .windows(2)
        .any(|w| w[0] == 0x89 && matches!(w[1], 0x0F | 0x02 | 0x07 | 0x11))
}

fn looks_like_get_formatter(bytes: &[u8]) -> bool {
    // `cmp qword [r+0x38], 0` — Type.klass on a System.Type / Il2CppClass.
    bytes.windows(5).any(|w| {
        w[0] == 0x48 && w[1] == 0x83 && w[3] == 0x38 && w[4] == 0x00 && w[2] & 0xF8 == 0x78
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MpRead {
    Int,
    Bool,
    Utf8,
    Value,
}

fn call_thunks_to(pe: &PeImage, va: u64, targets: &BTreeSet<u64>) -> bool {
    let Some(bytes) = pe.slice_va(va, 96) else {
        return false;
    };
    find_rel32_calls(va, bytes)
        .iter()
        .any(|c| targets.contains(c))
}

fn memorypack_members_from_reads(
    target: &str,
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    kinds: &[MpRead],
) -> Vec<MemorypackMember> {
    let mut params = target_param_fields(meta, ts, target);
    let mut n_int = 0u32;
    let mut n_bool = 0u32;
    let mut n_str = 0u32;
    let mut out = Vec::new();
    for kind in kinds {
        let member = match kind {
            MpRead::Int => {
                n_int += 1;
                MemorypackMember {
                    name: if n_int == 1 {
                        "_ID".into()
                    } else {
                        format!("int{n_int}")
                    },
                    ty: "int".into(),
                    collection_encoding: None,
                }
            }
            MpRead::Bool => {
                n_bool += 1;
                MemorypackMember {
                    name: format!("bool{n_bool}"),
                    ty: "bool".into(),
                    collection_encoding: None,
                }
            }
            MpRead::Utf8 => {
                n_str += 1;
                let name = if n_str == 1 {
                    "_uid".into()
                } else if n_str == 2 {
                    "string2".into()
                } else {
                    format!("string{n_str}")
                };
                MemorypackMember {
                    name,
                    ty: "string".into(),
                    collection_encoding: Some("utf8".into()),
                }
            }
            MpRead::Value => {
                let (name, ty) = params
                    .pop_front()
                    .unwrap_or_else(|| (format!("value{}", out.len()), "object".into()));
                MemorypackMember {
                    name,
                    ty,
                    collection_encoding: None,
                }
            }
        };
        out.push(member);
    }
    if n_str >= 3 {
        if let Some(last) = out.iter_mut().rev().find(|m| m.ty == "string") {
            last.name = "_param1".into();
        }
        if let Some(p) = out
            .iter_mut()
            .find(|m| m.ty.starts_with("Beyond.Gameplay.Actions.Param`1<string>"))
        {
            p.name = "_eventName".into();
        }
    }
    out
}

fn target_param_fields(
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    target: &str,
) -> std::collections::VecDeque<(String, String)> {
    let mut out = std::collections::VecDeque::new();
    for (ti, td) in meta.type_defs.iter().enumerate() {
        if ts.typedef_full_name(ti as i32) != target {
            continue;
        }
        if td.field_count == 0 || td.field_index < 0 {
            break;
        }
        let start = td.field_index as usize;
        for local in 0..td.field_count as usize {
            let Some(f) = meta.fields.get(start + local) else {
                break;
            };
            let fname = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
            let fty = ts.name_of_index(f.type_index);
            if fty.contains("Param`1") {
                out.push_back((fname, fty));
            }
        }
        break;
    }
    out
}

/// Union tag switches live on Beyond `*ForMemoryPack` wrappers. IL2CPP places
/// the large maps on `.cctor`; `Formatter.Deserialize` is often a short thunk.
fn is_union_candidate(method: &crate::codegen::MethodVa) -> bool {
    if method.name != "Deserialize" && method.name != ".cctor" {
        return false;
    }
    method.declaring_name.contains("ForMemoryPack")
}

/// Decoder-facing `{ "TypeName": { "tag": "Concrete" } }`.
///
/// Keys are the union static type, its wrapper, and the leaf name when that
/// leaf is unique among recovered unions. Ambiguous leaves such as `Data`
/// are omitted so a decoder must use the schema field's full type name.
pub fn decoder_union_map(unions: &[UnionTable]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut alias_count: BTreeMap<String, usize> = BTreeMap::new();
    for u in unions {
        for alias in union_aliases(&u.static_type) {
            *alias_count.entry(alias).or_insert(0) += 1;
        }
    }
    let mut map = BTreeMap::new();
    for u in unions {
        map.insert(u.static_type.clone(), u.tags.clone());
        if !u.wrapper_type.is_empty() && u.wrapper_type != u.static_type {
            map.entry(u.wrapper_type.clone())
                .or_insert_with(|| u.tags.clone());
        }
        for alias in union_aliases(&u.static_type) {
            if alias_count.get(&alias).copied().unwrap_or(0) == 1
                && alias != u.static_type
                && alias != u.wrapper_type
            {
                map.entry(alias).or_insert_with(|| u.tags.clone());
            }
        }
    }
    map
}

fn type_leaf(name: &str) -> &str {
    name.rsplit(['.', '+']).next().unwrap_or(name)
}

fn union_aliases(static_type: &str) -> Vec<String> {
    let mut out = vec![type_leaf(static_type).to_string()];
    if let Some((_, nested)) = static_type.rsplit_once('.') {
        if nested.contains('+') {
            let parts: Vec<&str> = nested.split('+').collect();
            if parts.len() >= 2 {
                out.push(format!(
                    "{}+{}",
                    parts[parts.len() - 2],
                    parts[parts.len() - 1]
                ));
            }
        }
    }
    out
}

fn load_pdata(pe: &PeImage) -> Vec<PdataFn> {
    let Some(sec) = pe.section_by_name(".pdata") else {
        return Vec::new();
    };
    let start = sec.raw_ptr as usize;
    let end = (start + sec.raw_size as usize).min(pe.data.len());
    let mut out = Vec::new();
    let mut off = start;
    while off + 12 <= end {
        let begin = u32::from_le_bytes(pe.data[off..off + 4].try_into().unwrap());
        let finish = u32::from_le_bytes(pe.data[off + 4..off + 8].try_into().unwrap());
        if finish > begin {
            out.push(PdataFn {
                begin_rva: begin,
                end_rva: finish,
            });
        }
        off += 12;
    }
    out
}

fn method_windows(pe: &PeImage, pdata: &[PdataFn], va: u64) -> Vec<(u64, u64)> {
    let entry = function_bounds(pe, pdata, va).unwrap_or((va, va.saturating_add(0x100)));
    let mut out = vec![(va, entry.1.max(va + 24))];
    let entry_size = entry.1.saturating_sub(entry.0);
    if entry_size < COLD_ENTRY_MAX {
        let mut tails = Vec::new();
        if let Some(tail) = thunk_target(pe, entry.0, entry.1) {
            tails.push(tail);
        }
        if let Some(tail) = first_far_branch(pe, entry.0, entry.1) {
            tails.push(tail);
        }
        for tail in tails {
            if let Some(tb) = function_bounds(pe, pdata, tail) {
                if tb.0 != entry.0 && !out.iter().any(|&(a, _)| a == tb.0) {
                    out.push(tb);
                }
            }
        }
    }
    out
}

/// `jmp rel32` / `call rel32` only as the first instruction of a short
/// `.pdata` entry (optional `endbr64`). Bytewise `E9` matching is rejected:
/// that opcode appears inside RIP-relative displacements.
fn thunk_target(pe: &PeImage, begin: u64, end: u64) -> Option<u64> {
    let size = end.saturating_sub(begin) as usize;
    let bytes = pe.slice_va(begin, size.min(16))?;
    let mut i = 0usize;
    if bytes.len() >= 4
        && bytes[0] == 0xF3
        && bytes[1] == 0x0F
        && bytes[2] == 0x1E
        && bytes[3] == 0xFA
    {
        i = 4;
    }
    let op = *bytes.get(i)?;
    if op != 0xE9 && op != 0xE8 {
        return None;
    }
    if bytes.len() < i + 5 {
        return None;
    }
    let rel = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?);
    let target = begin + i as u64 + 5 + rel as i64 as u64;
    if target < begin || target >= end {
        Some(target)
    } else {
        None
    }
}

/// Follow `jcc rel32` that leaves the `.pdata` entry. Unconditional `jmp rel32`
/// (`E9`) is not scanned here: that opcode appears inside RIP-relative
/// displacements (`cmp byte [rip+disp], 0` contains `E9`) and would stitch a
/// 25-byte thunk onto a neighbour's `.cctor`. Leading `E9` thunks are handled
/// by `thunk_target`.
fn first_far_branch(pe: &PeImage, begin: u64, end: u64) -> Option<u64> {
    let size = end.saturating_sub(begin) as usize;
    let bytes = pe.slice_va(begin, size)?;
    let mut i = 0usize;
    while i + 6 <= bytes.len() {
        if bytes[i] == 0x0F && (0x80..=0x8F).contains(&bytes[i + 1]) {
            let rel = i32::from_le_bytes(bytes[i + 2..i + 6].try_into().ok()?);
            let target = begin + i as u64 + 6 + rel as i64 as u64;
            if target < begin || target >= end {
                return Some(target);
            }
        }
        i += 1;
    }
    None
}

fn function_bounds(pe: &PeImage, pdata: &[PdataFn], va: u64) -> Option<(u64, u64)> {
    if va < pe.image_base {
        return None;
    }
    let rva = (va - pe.image_base) as u32;
    let mut lo = 0usize;
    let mut hi = pdata.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if pdata[mid].begin_rva <= rva {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let f = &pdata[lo - 1];
    if rva >= f.begin_rva && rva < f.end_rva {
        return Some((
            pe.image_base + f.begin_rva as u64,
            pe.image_base + f.end_rva as u64,
        ));
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn build_union(
    pe: &PeImage,
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    max_tag: i32,
    table_rva: u32,
    method: &crate::codegen::MethodVa,
    wrapper_by_target_td: &BTreeMap<usize, String>,
    target_name_by_td: &BTreeMap<usize, String>,
    target_name_by_wrapper_td: &BTreeMap<usize, String>,
) -> Option<UnionTable> {
    if !(1..=4096).contains(&max_tag) {
        return None;
    }
    let table_va = pe.image_base + table_rva as u64;
    let mut tags = BTreeMap::new();
    let mut evidence = Vec::new();
    let mut skipped = Vec::new();
    for tag in 0..=max_tag {
        let Some(rel) = pe.read_u32_va(table_va + (tag as u64) * 4) else {
            skipped.push(tag);
            continue;
        };
        let mut case_va = pe.image_base + rel as u64;
        case_va = follow_jmps(pe, case_va, 6);
        let Some(type_index) = find_typeinfo_index(pe, case_va) else {
            skipped.push(tag);
            continue;
        };
        let Some(td) = typedef_from_type_index(pe, ts, type_index) else {
            skipped.push(tag);
            continue;
        };
        let type_name = target_name_by_td
            .get(&td)
            .cloned()
            .or_else(|| target_name_by_wrapper_td.get(&td).cloned())
            .unwrap_or_else(|| ts.typedef_full_name(td as i32));
        let wrapper = wrapper_by_target_td.get(&td).cloned().or_else(|| {
            target_name_by_wrapper_td
                .contains_key(&td)
                .then(|| ts.typedef_full_name(td as i32))
        });
        tags.insert(tag.to_string(), type_name.clone());
        evidence.push(UnionTag {
            tag,
            type_name,
            wrapper_type: wrapper,
            typedef_index: td,
            case_va: format!("{case_va:#x}"),
        });
    }
    if tags.len() < 2 {
        return None;
    }
    let (static_type, wrapper_type) =
        union_owner(meta, ts, method.typedef_index, target_name_by_wrapper_td);
    Some(UnionTable {
        static_type,
        wrapper_type,
        formatter_type: method.declaring_name.clone(),
        deserialize_va: format!("{:#x}", method.va),
        max_tag,
        jumptable_rva: format!("{table_rva:#x}"),
        tags,
        evidence,
        skipped,
        status: "native_jumptable".into(),
    })
}

fn union_owner(
    meta: &Metadata,
    ts: &TypeSystem<'_>,
    formatter_td: usize,
    target_by_typedef: &BTreeMap<usize, String>,
) -> (String, String) {
    let td = &meta.type_defs[formatter_td];
    let wrapper_td = ts
        .typedef_index_of(td.declaring_type_index)
        .map(|i| i as usize)
        .unwrap_or(formatter_td);
    let wrapper_name = meta
        .type_name(&meta.type_defs[wrapper_td])
        .unwrap_or_else(|_| "?".into());
    let static_type = target_by_typedef
        .get(&wrapper_td)
        .cloned()
        .unwrap_or(wrapper_name.clone());
    (static_type, wrapper_name)
}

fn union_is_plausible(table: &UnionTable) -> bool {
    let unique = table.tags.values().collect::<HashSet<_>>().len();
    unique >= 2 && unique * 5 >= table.tags.len() * 4
}

fn better_union(best: Option<UnionTable>, candidate: UnionTable) -> UnionTable {
    match best {
        None => candidate,
        Some(cur) => pick_union(cur, candidate),
    }
}

fn merge_by_jumptable(best: &mut BTreeMap<String, UnionTable>, candidate: UnionTable) {
    match best.remove(&candidate.jumptable_rva) {
        None => {
            best.insert(candidate.jumptable_rva.clone(), candidate);
        }
        Some(cur) => {
            let keep = pick_union(cur, candidate);
            best.insert(keep.jumptable_rva.clone(), keep);
        }
    }
}

fn pick_union(cur: UnionTable, candidate: UnionTable) -> UnionTable {
    let cu = cur.tags.values().collect::<HashSet<_>>().len();
    let nu = candidate.tags.values().collect::<HashSet<_>>().len();
    if nu > cu || (nu == cu && candidate.tags.len() > cur.tags.len()) {
        candidate
    } else {
        cur
    }
}

fn merge_by_static_type(unions: Vec<UnionTable>) -> Vec<UnionTable> {
    let mut by_type: BTreeMap<String, UnionTable> = BTreeMap::new();
    for union in unions {
        match by_type.remove(&union.static_type) {
            None => {
                by_type.insert(union.static_type.clone(), union);
            }
            Some(cur) => {
                let keep = pick_union(cur, union);
                by_type.insert(keep.static_type.clone(), keep);
            }
        }
    }
    by_type.into_values().collect()
}

fn resolve_union_case(
    pe: &PeImage,
    ts: &mut TypeSystem<'_>,
    case_va: u64,
    wrapper_by_target_td: &BTreeMap<usize, String>,
    target_name_by_td: &BTreeMap<usize, String>,
    target_name_by_wrapper_td: &BTreeMap<usize, String>,
) -> Option<(String, Option<String>, usize)> {
    let case_va = follow_jmps(pe, case_va, 6);
    let type_index = find_typeinfo_index(pe, case_va)?;
    let td = typedef_from_type_index(pe, ts, type_index)?;
    let type_name = target_name_by_td
        .get(&td)
        .cloned()
        .or_else(|| target_name_by_wrapper_td.get(&td).cloned())
        .unwrap_or_else(|| ts.typedef_full_name(td as i32));
    if type_name == "System.Type" || type_name.starts_with("System.") {
        return None;
    }
    let wrapper = wrapper_by_target_td.get(&td).cloned().or_else(|| {
        target_name_by_wrapper_td
            .contains_key(&td)
            .then(|| ts.typedef_full_name(td as i32))
    });
    Some((type_name, wrapper, td))
}

#[allow(clippy::too_many_arguments)]
fn build_union_from_cases(
    pe: &PeImage,
    meta: &Metadata,
    ts: &mut TypeSystem<'_>,
    cases: &[(i32, u64)],
    method: &crate::codegen::MethodVa,
    wrapper_by_target_td: &BTreeMap<usize, String>,
    target_name_by_td: &BTreeMap<usize, String>,
    target_name_by_wrapper_td: &BTreeMap<usize, String>,
) -> Option<UnionTable> {
    if cases.len() < 2 {
        return None;
    }
    let max_tag = cases.iter().map(|(tag, _)| *tag).max()?;
    if !(1..=4096).contains(&max_tag) {
        return None;
    }
    let mut tags = BTreeMap::new();
    let mut evidence = Vec::new();
    let mut seen = HashSet::new();
    for &(tag, case_va) in cases {
        if !seen.insert(tag) {
            continue;
        }
        let Some((type_name, wrapper, td)) = resolve_union_case(
            pe,
            ts,
            case_va,
            wrapper_by_target_td,
            target_name_by_td,
            target_name_by_wrapper_td,
        ) else {
            continue;
        };
        tags.insert(tag.to_string(), type_name.clone());
        evidence.push(UnionTag {
            tag,
            type_name,
            wrapper_type: wrapper,
            typedef_index: td,
            case_va: format!("{case_va:#x}"),
        });
    }
    if tags.len() < 2 {
        return None;
    }
    let (static_type, wrapper_type) =
        union_owner(meta, ts, method.typedef_index, target_name_by_wrapper_td);
    let recovered: HashSet<i32> = tags.keys().filter_map(|k| k.parse().ok()).collect();
    let skipped = (0..=max_tag).filter(|t| !recovered.contains(t)).collect();
    Some(UnionTable {
        static_type,
        wrapper_type,
        formatter_type: method.declaring_name.clone(),
        deserialize_va: format!("{:#x}", method.va),
        max_tag,
        jumptable_rva: format!("ifeq:{:#x}", method.va),
        tags,
        evidence,
        skipped,
        status: "native_ifeq".into(),
    })
}

/// Small unions (ConditionBase, HealProcessorBase, …) dispatch with
/// `ReadUnionHeader; test tag; je tag0; cmp tag, 1; jne fail` instead of a
/// `ja` jumptable. Each taken branch loads a TypeInfo slot.
fn find_ifeq_tag_groups(pe: Option<&PeImage>, begin: u64, bytes: &[u8]) -> Vec<Vec<(i32, u64)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 < bytes.len() {
        let after = match_movzx_r16(bytes, i).or_else(|| match_movzx_r8(bytes, i));
        if let Some(after) = after {
            if let Some(cases) = parse_ifeq_dispatch(pe, begin, bytes, after, 0, 0) {
                if cases.len() >= 2 {
                    out.push(cases);
                    i = after;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// `movzx r32, r/m16` (`0F B7 /r`), optional REX.
fn match_movzx_r16(bytes: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    if bytes.get(k)? & 0xF0 == 0x40 {
        k += 1;
    }
    if bytes.get(k) != Some(&0x0F) || bytes.get(k + 1) != Some(&0xB7) {
        return None;
    }
    let addr = modrm_addr_len(bytes.get(k + 2..)?)?;
    Some(k + 2 + addr)
}

fn parse_ifeq_dispatch(
    pe: Option<&PeImage>,
    begin: u64,
    bytes: &[u8],
    mut i: usize,
    mut acc: i32,
    depth: u32,
) -> Option<Vec<(i32, u64)>> {
    if depth > 4 {
        return None;
    }
    let mut cases = Vec::new();
    let mut guard = 0;
    while i + 6 < bytes.len() && guard < 16 {
        guard += 1;
        if let Some(len) = match_mov_reg_reg(bytes, i) {
            i += len;
            continue;
        }
        if let Some(len) = match_test_reg(bytes, i) {
            i += len;
            let Some((eq, target, jlen)) = match_jcc(bytes, i, begin) else {
                break;
            };
            i += jlen;
            if eq {
                cases.push((0, target));
            }
            continue;
        }
        if let Some((imm, len)) = match_cmp_reg_imm(bytes, i) {
            if !(0..=64).contains(&imm) {
                break;
            }
            i += len;
            let Some((eq, target, jlen)) = match_jcc(bytes, i, begin) else {
                break;
            };
            i += jlen;
            // After `sub tag, K` the register is already reduced, so
            // `cmp eax, N; je` is original tag acc+N (ExtraData tag 2).
            let tag = acc + imm;
            if !(0..=64).contains(&tag) {
                break;
            }
            if eq {
                cases.push((tag, target));
            } else {
                // `cmp tag, N; jne X` — fallthrough is tag N.
                cases.push((tag, begin.wrapping_add(i as u64)));
            }
            continue;
        }
        if let Some((imm, len)) = match_sub_reg_imm(bytes, i) {
            if !(1..=16).contains(&imm) {
                break;
            }
            i += len;
            let Some((eq, target, jlen)) = match_jcc(bytes, i, begin) else {
                break;
            };
            i += jlen;
            acc += imm;
            if !(0..=64).contains(&acc) {
                break;
            }
            if eq {
                // `sub tag, N; je` — original tag was the running sum.
                cases.push((acc, target));
            } else {
                // ExtraData: `test; je tag0; sub eax,1; jne cold` fallthrough is tag 1.
                cases.push((acc, begin.wrapping_add(i as u64)));
                if let Some(more) = follow_ifeq_cold(pe, begin, bytes, target, acc, depth) {
                    cases.extend(more);
                }
            }
            continue;
        }
        break;
    }
    if cases.is_empty() {
        return None;
    }
    Some(cases)
}

/// ExtraData tag 2 lives on a cold `jne` (`cmp eax,1; je UpperBody`).
fn follow_ifeq_cold(
    pe: Option<&PeImage>,
    begin: u64,
    bytes: &[u8],
    target: u64,
    acc: i32,
    depth: u32,
) -> Option<Vec<(i32, u64)>> {
    let end = begin.wrapping_add(bytes.len() as u64);
    if target >= begin && target < end {
        let j = (target - begin) as usize;
        return parse_ifeq_dispatch(pe, begin, bytes, j, acc, depth + 1);
    }
    let pe = pe?;
    let cold = pe.slice_va(target, 192)?;
    parse_ifeq_dispatch(Some(pe), target, cold, 0, acc, depth + 1)
}

/// `mov r32, r32` (`8B /r` or `89 /r` with mod=11). ExtraData copies the
/// union tag into eax before `test`/`sub`.
fn match_mov_reg_reg(bytes: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    if bytes.get(k)? & 0xF0 == 0x40 {
        k += 1;
    }
    let op = *bytes.get(k)?;
    if op != 0x8B && op != 0x89 {
        return None;
    }
    let modrm = *bytes.get(k + 1)?;
    if modrm >> 6 != 0b11 {
        return None;
    }
    Some(k - i + 2)
}

/// `sub r/m32, imm8` (`83 /5 ib`). Compilers fold consecutive union tags
/// as `sub eax, 1; je/jne` instead of `cmp eax, N`.
fn match_sub_reg_imm(bytes: &[u8], i: usize) -> Option<(i32, usize)> {
    let mut k = i;
    if bytes.get(k) == Some(&0x66) || matches!(bytes.get(k), Some(b) if b & 0xF0 == 0x40) {
        k += 1;
    }
    if bytes.get(k) != Some(&0x83) {
        return None;
    }
    let modrm = *bytes.get(k + 1)?;
    if (modrm >> 3) & 7 != 5 {
        return None;
    }
    let addr = modrm_addr_len(&bytes[k + 1..])?;
    let imm = *bytes.get(k + 1 + addr)? as i8 as i32;
    Some((imm, k - i + 1 + addr + 1))
}

fn match_test_reg(bytes: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    if bytes.get(k) == Some(&0x66) || matches!(bytes.get(k), Some(b) if b & 0xF0 == 0x40) {
        k += 1;
    }
    if bytes.get(k) != Some(&0x85) {
        return None;
    }
    let addr = modrm_addr_len(bytes.get(k + 1..)?)?;
    Some(k - i + 1 + addr)
}

fn match_cmp_reg_imm(bytes: &[u8], i: usize) -> Option<(i32, usize)> {
    let mut k = i;
    if bytes.get(k) == Some(&0x66) || matches!(bytes.get(k), Some(b) if b & 0xF0 == 0x40) {
        k += 1;
    }
    if bytes.get(k) != Some(&0x83) {
        return None;
    }
    let modrm = *bytes.get(k + 1)?;
    if (modrm >> 3) & 7 != 7 {
        return None;
    }
    let addr = modrm_addr_len(&bytes[k + 1..])?;
    let imm = *bytes.get(k + 1 + addr)? as i8 as i32;
    Some((imm, k - i + 1 + addr + 1))
}

fn match_jcc(bytes: &[u8], i: usize, begin: u64) -> Option<(bool, u64, usize)> {
    match bytes.get(i).copied()? {
        0x74 | 0x75 if bytes.len() > i + 1 => {
            let eq = bytes[i] == 0x74;
            let rel = bytes[i + 1] as i8 as i64;
            Some((
                eq,
                begin
                    .wrapping_add(i as u64)
                    .wrapping_add(2)
                    .wrapping_add(rel as u64),
                2,
            ))
        }
        0x0F if matches!(bytes.get(i + 1), Some(&0x84 | &0x85)) && bytes.len() >= i + 6 => {
            let eq = bytes[i + 1] == 0x84;
            let rel = i32::from_le_bytes(bytes[i + 2..i + 6].try_into().ok()?) as i64;
            Some((
                eq,
                begin
                    .wrapping_add(i as u64)
                    .wrapping_add(6)
                    .wrapping_add(rel as u64),
                6,
            ))
        }
        _ => None,
    }
}

fn record_struct_memcpy(
    pe: &PeImage,
    facts: &mut NativeFacts,
    declaring: &str,
    begin: u64,
    bytes: &[u8],
) {
    let mut counts = find_struct_memcpy_counts(bytes);
    for (width, n) in find_helper_struct_memcpy_counts(pe, begin, bytes) {
        let slot = counts.entry(width).or_insert(0);
        *slot = (*slot).max(n);
    }
    if counts.is_empty() {
        return;
    }
    let entry = facts
        .struct_memcpy
        .entry(declaring.to_string())
        .or_default();
    for (width, n) in counts {
        let slot = entry.entry(width).or_insert(0);
        *slot = (*slot).max(n);
    }
}

/// Inline unmanaged struct copies: `add [reader+0x50], N` with N in {2,8,16}.
/// InteractiveTemplateVariant copies Optional<enum>/float as 8 and Optional<bool> as 2.
pub fn find_struct_memcpy_counts(bytes: &[u8]) -> BTreeMap<i32, usize> {
    let mut counts = BTreeMap::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let mut k = i;
        if bytes[k] == 0x48 {
            k += 1;
        }
        if k + 3 < bytes.len() && bytes[k] == 0x83 {
            let modrm = bytes[k + 1];
            let op = (modrm >> 3) & 7;
            let mode = modrm >> 6;
            if op == 0 && mode == 1 {
                let disp = bytes[k + 2];
                let imm = bytes[k + 3] as i32;
                if disp == 0x50 && matches!(imm, 2 | 8 | 16) {
                    *counts.entry(imm).or_insert(0) += 1;
                    i = k + 4;
                    continue;
                }
            }
        }
        i += 1;
    }
    counts
}

/// SpawnerEnemyLibraryItem copies Optional<Vector3> as `mov edx, 16; call Advance(edx)`
/// (`add [reader+0x50], rdi`) instead of an immediate `add [reader+0x50], 16`.
fn find_helper_struct_memcpy_counts(
    pe: &PeImage,
    begin: u64,
    bytes: &[u8],
) -> BTreeMap<i32, usize> {
    let mut counts = BTreeMap::new();
    let mut i = 0usize;
    while i + 5 < bytes.len() {
        let Some((width, inst_len)) = match_mov_imm_2_8_16(&bytes[i..]) else {
            i += 1;
            continue;
        };
        let search = bytes[i + inst_len..].len().min(24);
        let window = &bytes[i + inst_len..i + inst_len + search];
        let mut j = 0usize;
        let mut found = false;
        while j + 5 <= window.len() {
            if window[j] == 0xE8 {
                let rel = i32::from_le_bytes(window[j + 1..j + 5].try_into().unwrap());
                let call_at = i + inst_len + j;
                let target = begin
                    .wrapping_add(call_at as u64)
                    .wrapping_add(5)
                    .wrapping_add(rel as i64 as u64);
                if callee_advances_reader(pe, target) {
                    *counts.entry(width).or_insert(0) += 1;
                    i = call_at + 5;
                    found = true;
                }
                break;
            }
            j += 1;
        }
        if found {
            continue;
        }
        i += inst_len;
    }
    counts
}

fn match_mov_imm_2_8_16(bytes: &[u8]) -> Option<(i32, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let mut i = 0usize;
    if bytes[0] & 0xF0 == 0x40 {
        i = 1;
        if bytes.len() < 2 {
            return None;
        }
    }
    let op = bytes[i];
    if (0xB8..=0xBF).contains(&op) {
        if bytes.len() < i + 5 {
            return None;
        }
        let imm = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?);
        if matches!(imm, 2 | 8 | 16) {
            return Some((imm, i + 5));
        }
    }
    if (0xB0..=0xB7).contains(&op) {
        let imm = *bytes.get(i + 1)? as i32;
        if matches!(imm, 2 | 8 | 16) {
            return Some((imm, i + 2));
        }
    }
    None
}

fn callee_advances_reader(pe: &PeImage, va: u64) -> bool {
    let Some(bytes) = pe.slice_va(va, 80) else {
        return false;
    };
    callee_has_reader_advance(bytes)
}

/// `add [reg+0x50], r64` (`48 01 /r` with disp8 0x50) — MemoryPackReader.Advance.
pub fn callee_has_reader_advance(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if bytes[i] == 0x48 && bytes[i + 1] == 0x01 {
            let modrm = bytes[i + 2];
            if modrm >> 6 == 1 && bytes[i + 3] == 0x50 {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn record_array_strides(
    pe: &PeImage,
    facts: &mut NativeFacts,
    declaring: &str,
    begin: u64,
    bytes: &[u8],
) {
    for target in find_rel32_calls(begin, bytes) {
        if !pe.is_executable_va(target) {
            continue;
        }
        let Some(callee) = pe.slice_va(target, 512) else {
            continue;
        };
        // Specialized T[] memcpy helpers have one stride (GameplayTag lea*4
        // at +0xe3, FKeyframe shl 5). A 192-byte window missed the lea.
        if let Some(stride) = find_unmanaged_array_stride(callee) {
            facts
                .array_strides
                .entry(declaring.to_string())
                .or_default()
                .insert(stride);
        }
    }
}

fn find_rel32_calls(begin: u64, bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().unwrap());
            out.push(
                begin
                    .wrapping_add(i as u64)
                    .wrapping_add(5)
                    .wrapping_add(rel as i64 as u64),
            );
            i += 5;
            continue;
        }
        i += 1;
    }
    out
}

/// Native `T[]` reader: i32 count, then `count * stride` memcpy.
/// FKeyframe keys: `shl r14d, 5` (stride 32). GameplayTag[]: `lea r14d, [rdi*4]`.
/// Requires remaining>=4 and cmp -1 in the same helper, and exactly one stride,
/// so a wrapper Deserialize that also has unrelated `imul 4` is not marked.
pub fn find_unmanaged_array_stride(bytes: &[u8]) -> Option<i32> {
    if !has_remaining_ge4(bytes) || !has_cmp_neg1(bytes) {
        return None;
    }
    let mut strides = Vec::new();
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        if let Some((stride, n)) = match_shl_power(&bytes[i..]) {
            if (2..=256).contains(&stride) {
                strides.push(stride);
            }
            i += n;
            continue;
        }
        if let Some((stride, n)) = match_lea_scaled_index(&bytes[i..]) {
            if (2..=256).contains(&stride) {
                strides.push(stride);
            }
            i += n;
            continue;
        }
        i += 1;
    }
    strides.sort_unstable();
    strides.dedup();
    match strides.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}

/// Every memcpy-array stride in `bytes`. A specialized helper has one;
/// a wrapper Deserialize may call several (GameplayTag[] 4 and FKeyframe[] 32).
pub fn find_all_unmanaged_array_strides(bytes: &[u8]) -> BTreeSet<i32> {
    let mut out = BTreeSet::new();
    if !has_remaining_ge4(bytes) || !has_cmp_neg1(bytes) {
        // Wrapper Deserialize often has the remaining/null checks in the
        // callee; still recover a stride sitting next to `cmp r32, -1`.
        out.extend(strides_near_cmp_neg1(bytes));
        return out;
    }
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        if let Some((stride, n)) = match_shl_power(&bytes[i..]) {
            if (2..=256).contains(&stride) {
                out.insert(stride);
            }
            i += n;
            continue;
        }
        if let Some((stride, n)) = match_lea_scaled_index(&bytes[i..]) {
            if (2..=256).contains(&stride) {
                out.insert(stride);
            }
            i += n;
            continue;
        }
        if let Some((stride, n)) = match_imul_imm(&bytes[i..]) {
            if (2..=256).contains(&stride) {
                out.insert(stride);
            }
            i += n;
            continue;
        }
        i += 1;
    }
    out.extend(strides_near_cmp_neg1(bytes));
    out
}

fn strides_near_cmp_neg1(bytes: &[u8]) -> BTreeSet<i32> {
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        let is_cmp_neg1 = bytes[i] == 0x83 && {
            let modrm = bytes[i + 1];
            (modrm >> 3) & 7 == 7 && (modrm >> 6) == 3 && bytes[i + 2] == 0xFF
        };
        if !is_cmp_neg1 {
            i += 1;
            continue;
        }
        let end = bytes.len().min(i + 96);
        let mut j = i;
        while j < end {
            if let Some((stride, n)) = match_shl_power(&bytes[j..])
                .or_else(|| match_lea_scaled_index(&bytes[j..]))
                .or_else(|| match_imul_imm(&bytes[j..]))
            {
                if (2..=256).contains(&stride) {
                    out.insert(stride);
                }
                j += n;
                continue;
            }
            j += 1;
        }
        i += 3;
    }
    out
}

fn match_imul_imm(bytes: &[u8]) -> Option<(i32, usize)> {
    let mut k = 0usize;
    if bytes.first()? & 0xF0 == 0x40 {
        k = 1;
    }
    match bytes.get(k)? {
        0x6B => {
            let imm = *bytes.get(k + 2)? as i8 as i32;
            if matches!(imm, 2 | 4 | 8 | 16 | 32) {
                Some((imm, k + 3))
            } else {
                None
            }
        }
        0x69 => {
            let imm = i32::from_le_bytes(bytes.get(k + 2..k + 6)?.try_into().ok()?);
            if matches!(imm, 2 | 4 | 8 | 16 | 32) {
                Some((imm, k + 6))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn has_remaining_ge4(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        if bytes[i] == 0x83 {
            let modrm = bytes[i + 1];
            if (modrm >> 3) & 7 == 7
                && (modrm >> 6) == 1
                && bytes[i + 2] == 0x30
                && bytes[i + 3] == 4
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn has_cmp_neg1(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == 0x83 {
            let modrm = bytes[i + 1];
            if (modrm >> 3) & 7 == 7 && (modrm >> 6) == 3 && bytes[i + 2] == 0xFF {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn match_shl_power(bytes: &[u8]) -> Option<(i32, usize)> {
    let mut k = 0usize;
    if bytes.first()? & 0xF0 == 0x40 {
        k = 1;
    }
    if bytes.get(k) != Some(&0xC1) {
        return None;
    }
    let modrm = *bytes.get(k + 1)?;
    if (modrm >> 3) & 7 != 4 || (modrm >> 6) != 3 {
        return None;
    }
    let imm = *bytes.get(k + 2)?;
    if !(1..=8).contains(&imm) {
        return None;
    }
    Some((1i32 << imm, k + 3))
}

fn match_lea_scaled_index(bytes: &[u8]) -> Option<(i32, usize)> {
    let mut k = 0usize;
    if bytes.first()? & 0xF0 == 0x40 {
        k = 1;
    }
    if bytes.get(k) != Some(&0x8D) {
        return None;
    }
    let modrm = *bytes.get(k + 1)?;
    if modrm & 7 != 4 {
        return None;
    }
    let sib = *bytes.get(k + 2)?;
    let scale = 1i32 << (sib >> 6);
    if scale == 1 {
        return None;
    }
    let mod_ = modrm >> 6;
    let base = sib & 7;
    let disp = match (mod_, base) {
        (0, 5) => 4usize,
        (0, _) => 0,
        (1, _) => 1,
        (2, _) => 4,
        _ => return None,
    };
    Some((scale, k + 3 + disp))
}

/// Object-header byte compare: `movzx r32, r/m8` then `cmp r8, N`.
/// Distinguishes from union tags, which `movzx` a u16.
fn find_inline_member_count(bytes: &[u8]) -> Option<i32> {
    let mut found = None;
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        let Some(after) = match_movzx_r8(bytes, i) else {
            i += 1;
            continue;
        };
        let window_end = bytes.len().min(after + 192);
        let mut saw_null = false;
        let mut j = after;
        while j + 3 < window_end {
            if let Some((imm, len)) = match_cmp_r8_imm(&bytes[j..]) {
                if imm == 0xFF {
                    saw_null = true;
                } else if (1..=128).contains(&imm) && (saw_null || found.is_none()) {
                    found = Some(imm);
                }
                j += len;
                continue;
            }
            j += 1;
        }
        i = after;
    }
    found
}

fn match_movzx_r8(bytes: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    if bytes.get(k)? & 0xF0 == 0x40 {
        k += 1;
    }
    if bytes.get(k) != Some(&0x0F) || bytes.get(k + 1) != Some(&0xB6) {
        return None;
    }
    let addr = modrm_addr_len(bytes.get(k + 2..)?)?;
    Some(k + 2 + addr)
}

fn match_cmp_r8_imm(bytes: &[u8]) -> Option<(i32, usize)> {
    let mut i = 0usize;
    if bytes.first().copied()? & 0xF0 == 0x40 {
        i = 1;
    }
    match bytes.get(i).copied()? {
        0x3C if i == 0 || bytes[0] & 0xF0 == 0x40 => {
            let imm = *bytes.get(i + 1)? as i32;
            Some((imm, i + 2))
        }
        0x80 => {
            let modrm = *bytes.get(i + 1)?;
            if (modrm >> 3) & 7 != 7 {
                return None;
            }
            let addr = modrm_addr_len(&bytes[i + 1..])?;
            let imm = *bytes.get(i + 1 + addr)? as i32;
            Some((imm, i + 1 + addr + 1))
        }
        _ => None,
    }
}

fn jumptable_is_code(pe: &PeImage, table_rva: u32, max_tag: i32) -> bool {
    let n = (max_tag as u64).saturating_add(1);
    if n == 0 {
        return false;
    }
    let table_va = pe.image_base + table_rva as u64;
    let mut exec = 0u64;
    for tag in 0..n {
        let Some(rel) = pe.read_u32_va(table_va + tag * 4) else {
            continue;
        };
        if pe.is_executable_va(pe.image_base + rel as u64) {
            exec += 1;
        }
    }
    exec * 2 >= n
}

/// `cmp tag, N; jne` targets. SpawnerActionData keeps tag N on the
/// fallthrough and sends 0..N-1 to a cold `ja` jumptable.
fn find_cmp_jne_targets(bytes: &[u8], begin: u64) -> Vec<(i32, u64, u64)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 10 < bytes.len() {
        let Some((imm, inst_len)) = parse_cmp_imm(&bytes[i..]) else {
            i += 1;
            continue;
        };
        if !(2..=4096).contains(&imm) {
            i += 1;
            continue;
        }
        let after = i + inst_len;
        let Some((eq, target, jlen)) = match_jcc(bytes, after, begin) else {
            i += 1;
            continue;
        };
        if eq {
            i += 1;
            continue;
        }
        let fallthrough = begin.wrapping_add((after + jlen) as u64);
        out.push((imm, target, fallthrough));
        i += 1;
    }
    out
}

/// Cold half of a split switch: `ja fail` then scaled-index jumptable.
fn find_ja_jumptable(bytes: &[u8]) -> Option<u32> {
    let ja_len = match_ja_prefix(bytes)?;
    let window = bytes.get(ja_len..)?;
    for k in 0..window.len().min(48) {
        if let Some((rva, load_len)) = parse_scaled_index_load(&window[k..]) {
            if has_index_dispatch(window.get(k + load_len..).unwrap_or(&[])) {
                return Some(rva);
            }
        }
    }
    None
}

fn find_jumptables_in_bytes(bytes: &[u8]) -> Vec<(i32, u32)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 16 < bytes.len() {
        let Some((imm, inst_len)) = parse_cmp_imm(&bytes[i..]) else {
            i += 1;
            continue;
        };
        if !(1..=4096).contains(&imm) {
            i += 1;
            continue;
        }
        let after = i + inst_len;
        let Some(ja_len) = match_ja_prefix(bytes.get(after..).unwrap_or(&[])) else {
            i += 1;
            continue;
        };
        let load_at = after + ja_len;
        if load_at >= bytes.len() {
            break;
        }
        let window_end = bytes.len().min(load_at + 96);
        let window = &bytes[load_at..window_end];
        for k in 0..window.len() {
            if let Some((rva, load_len)) = parse_scaled_index_load(&window[k..]) {
                if has_index_dispatch(window.get(k + load_len..).unwrap_or(&[])) {
                    out.push((imm, rva));
                    break;
                }
            }
        }
        i += 1;
    }
    out
}

/// `ja` / `jae` rel8 or rel32 immediately after the tag compare.
fn match_ja_prefix(bytes: &[u8]) -> Option<usize> {
    match bytes.first().copied()? {
        0x77 | 0x73 if bytes.len() >= 2 => Some(2),
        0x0F if matches!(bytes.get(1), Some(&0x87 | &0x83)) && bytes.len() >= 6 => Some(6),
        _ => None,
    }
}

/// CMP r/m32, imm (opcodes `3D` / `81 /7` / `83 /7`), optional REX.
fn parse_cmp_imm(bytes: &[u8]) -> Option<(i32, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let mut i = 0usize;
    if bytes[0] & 0xF0 == 0x40 {
        i = 1;
        if bytes.len() < 2 {
            return None;
        }
    }
    match bytes.get(i).copied()? {
        0x3D => {
            if bytes.len() < i + 5 {
                return None;
            }
            let imm = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?);
            Some((imm, i + 5))
        }
        0x81 | 0x83 => {
            let imm8 = bytes[i] == 0x83;
            let addr = modrm_addr_len(&bytes[i + 1..])?;
            let modrm = *bytes.get(i + 1)?;
            if (modrm >> 3) & 7 != 7 {
                return None;
            }
            let imm_at = i + 1 + addr;
            if imm8 {
                let imm = *bytes.get(imm_at)? as i8 as i32;
                Some((imm, imm_at + 1))
            } else if bytes.len() >= imm_at + 4 {
                let imm = i32::from_le_bytes(bytes[imm_at..imm_at + 4].try_into().ok()?);
                Some((imm, imm_at + 4))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn modrm_addr_len(bytes: &[u8]) -> Option<usize> {
    let modrm = *bytes.first()?;
    let mod_bits = modrm >> 6;
    let rm = modrm & 7;
    if mod_bits == 3 {
        return Some(1);
    }
    let mut n = 1usize;
    let mut sib_base = None;
    if rm == 4 {
        let sib = *bytes.get(1)?;
        sib_base = Some(sib & 7);
        n += 1;
    }
    match mod_bits {
        0 if rm == 5 || sib_base == Some(5) => n += 4,
        1 => n += 1,
        2 => n += 4,
        _ => {}
    }
    if bytes.len() < n {
        return None;
    }
    Some(n)
}

/// `mov r32, [base + index*4 + disp32]` with optional REX.
fn parse_scaled_index_load(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut i = 0usize;
    if bytes.first().copied()? & 0xF0 == 0x40 {
        i = 1;
    }
    if bytes.get(i) != Some(&0x8B) {
        return None;
    }
    let modrm = *bytes.get(i + 1)?;
    if modrm & 0xC0 != 0x80 || modrm & 7 != 4 {
        return None;
    }
    let sib = *bytes.get(i + 2)?;
    if sib >> 6 != 2 {
        return None;
    }
    if bytes.len() < i + 7 {
        return None;
    }
    let rva = u32::from_le_bytes(bytes[i + 3..i + 7].try_into().ok()?);
    Some((rva, i + 7))
}

fn has_index_dispatch(bytes: &[u8]) -> bool {
    let n = bytes.len().min(12);
    let slice = &bytes[..n];
    let has_add = slice.contains(&0x03);
    let has_jmp = slice
        .windows(2)
        .any(|w| w[0] == 0xFF && (0xE0..=0xE7).contains(&w[1]));
    has_add && has_jmp
}

fn follow_jmps(pe: &PeImage, mut va: u64, limit: usize) -> u64 {
    for _ in 0..limit {
        let Some(b0) = pe.read_u8_va(va) else {
            return va;
        };
        if b0 == 0xEB {
            let Some(rel) = pe.read_u8_va(va + 1) else {
                return va;
            };
            va = va.wrapping_add(2).wrapping_add(rel as i8 as i64 as u64);
            continue;
        }
        if b0 == 0xE9 {
            let Some(rel) = pe.read_i32_va(va + 1) else {
                return va;
            };
            va = va.wrapping_add(5).wrapping_add(rel as i64 as u64);
            continue;
        }
        return va;
    }
    va
}

fn find_typeinfo_index(pe: &PeImage, start: u64) -> Option<i32> {
    for off in 0..256u64 {
        let va = start + off;
        let Some(b0) = pe.read_u8_va(va) else {
            break;
        };
        // 48 8B 0D/15/05 disp32  mov r64, [rip+disp]
        if b0 != 0x48 || pe.read_u8_va(va + 1) != Some(0x8B) {
            continue;
        }
        let Some(modrm) = pe.read_u8_va(va + 2) else {
            continue;
        };
        if modrm & 0xC7 != 0x05 {
            continue;
        }
        let Some(rel) = pe.read_i32_va(va + 3) else {
            continue;
        };
        let slot = va.wrapping_add(7).wrapping_add(rel as i64 as u64);
        let Some(enc) = pe.read_u64_va(slot) else {
            continue;
        };
        if enc & 1 == 0 {
            continue;
        }
        let usage = ((enc >> 29) & 7) as u32;
        if usage != 1 {
            continue;
        }
        return Some(((enc >> 1) & 0x0FFF_FFFF) as i32);
    }
    None
}

fn typedef_from_type_index(pe: &PeImage, ts: &TypeSystem<'_>, type_index: i32) -> Option<usize> {
    if type_index < 0 || type_index as usize >= ts.type_ptrs.len() {
        return None;
    }
    let ty_va = ts.type_ptrs[type_index as usize];
    let data = pe.read_u64_va(ty_va)?;
    let td = data as i32;
    if td >= 0 && (td as usize) < ts.meta.type_defs.len() {
        Some(td as usize)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_imm_register_and_stack_forms() {
        assert_eq!(
            parse_cmp_imm(&hex("817c243053050000")),
            Some((0x553, 8)),
            "cmp dword [rsp+0x30], 0x553"
        );
        assert_eq!(
            parse_cmp_imm(&hex("81febe010000")),
            Some((0x1BE, 6)),
            "cmp esi, 0x1BE"
        );
        assert_eq!(
            parse_cmp_imm(&hex("83f814")),
            Some((0x14, 3)),
            "cmp eax, 0x14"
        );
        assert_eq!(
            parse_cmp_imm(&hex("83fe31")),
            Some((0x31, 3)),
            "cmp esi, 0x31"
        );
        assert_eq!(
            parse_cmp_imm(&hex("3def000000")),
            Some((0xEF, 5)),
            "cmp eax, 0xEF"
        );
        assert_eq!(
            parse_cmp_imm(&hex("83fe0a7545")),
            Some((0x0A, 3)),
            "cmp esi, 0x0A still parses; ja is required separately"
        );
    }

    #[test]
    fn scaled_index_disp32_forms() {
        assert_eq!(
            parse_scaled_index_load(&hex("8b848108e0a904")),
            Some((0x04A9_E008, 7))
        );
        assert_eq!(
            parse_scaled_index_load(&hex("8b8cb2c8a4cc05")),
            Some((0x05CC_A4C8, 7))
        );
        assert_eq!(
            parse_scaled_index_load(&hex("418b8cb780270606")),
            Some((0x0606_2780, 8))
        );
    }

    #[test]
    fn action_base_rip_relative_switch() {
        // cmp [rsp+0x30], 0x553; ja; movsxd; lea; mov eax, [rcx+rax*4+rva]; add; jmp
        let bytes =
            hex("817c2430530500000f87603500004863442430488d0dce185cfb8b848108e0a9044803c1ffe0");
        assert_eq!(find_jumptables_in_bytes(&bytes), vec![(0x553, 0x04A9_E008)]);
    }

    #[test]
    fn ability_action_esi_switch() {
        let bytes = hex("81febe0100000f8783860000488d150ce233fa8b8cb2c8a4cc054803caffe1");
        assert_eq!(find_jumptables_in_bytes(&bytes), vec![(0x1BE, 0x05CC_A4C8)]);
    }

    #[test]
    fn condition_runtime_r15_switch() {
        let bytes = hex("83fe310f870a0b0000418b8cb7802706064903cfffe1");
        assert_eq!(find_jumptables_in_bytes(&bytes), vec![(0x31, 0x0606_2780)]);
    }

    #[test]
    fn jae_rel32_switch() {
        let bytes = hex("83fe050f830a0000008b8cb2c8a4cc054803caffe1");
        assert_eq!(find_jumptables_in_bytes(&bytes), vec![(5, 0x05CC_A4C8)]);
    }

    #[test]
    fn jne_is_not_a_union_switch() {
        let bytes = hex("83fe0a7545488b0f");
        assert!(find_jumptables_in_bytes(&bytes).is_empty());
    }

    #[test]
    fn split_jne_records_cold_target_and_fallthrough() {
        // cmp esi, 5; jne rel32 to 0x2000; fallthrough
        let begin = 0x1000u64;
        let rel = (0x2000i64 - (begin as i64 + 3 + 6)) as i32;
        let mut bytes = hex("83fe05");
        bytes.extend_from_slice(&[0x0F, 0x85]);
        bytes.extend_from_slice(&rel.to_le_bytes());
        bytes.extend_from_slice(&hex("488b0b"));
        let hits = find_cmp_jne_targets(&bytes, begin);
        assert_eq!(hits, vec![(5, 0x2000, begin + 9)]);
    }

    #[test]
    fn split_cold_ja_is_a_jumptable() {
        // ja rel32; lea rdx,[rip]; mov ecx,[rdx+rsi*4+rva]; add rcx,rdx; jmp rcx
        let bytes = hex("0f8785010000488d1513ef88f88b8cb2a81277074803caffe1");
        assert_eq!(find_ja_jumptable(&bytes), Some(0x0777_12a8));
    }

    #[test]
    fn extra_data_ifeq_uses_sub_after_mov() {
        // movzx edi,[rsp+38]; mov eax,edi; test edi,edi; je tag0; sub eax,1; jne fail
        let begin = 0x1000u64;
        let bytes = hex("0fb77c24388bc785ff740a83e80175059090909090");
        let groups = find_ifeq_tag_groups(None, begin, &bytes);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0][0].0, 0);
        assert_eq!(groups[0][1].0, 1);
    }

    #[test]
    fn extra_data_ifeq_follows_cold_cmp_as_tag2() {
        // Hot: movzx; mov eax,edi; test; je tag0; sub eax,1; jne cold; tag1
        // Cold: cmp eax,1; je tag2  (eax already reduced, so original tag 2)
        let begin = 0x1000u64;
        let bytes = hex(
            "0fb77c24388bc785ff741983e8017505909090909083f8017405909090909090909090909090909090",
        );
        let groups = find_ifeq_tag_groups(None, begin, &bytes);
        assert_eq!(groups.len(), 1);
        let tags: Vec<i32> = groups[0].iter().map(|(t, _)| *t).collect();
        assert_eq!(tags, vec![0, 1, 2]);
    }

    #[test]
    fn extra_data_ifeq_uses_r8_tag() {
        // movzx eax, byte [rsp+38]; test eax,eax; je tag0; cmp eax,1; je tag1
        let begin = 0x1000u64;
        let bytes = hex("0fb644243885c0740a83f80174059090909090");
        let groups = find_ifeq_tag_groups(None, begin, &bytes);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0][0].0, 0);
        assert_eq!(groups[0][1].0, 1);
    }

    #[test]
    fn heal_processor_ifeq_uses_r32_test() {
        // movzx esi,[rsp+38]; test esi,esi; je tag0; cmp esi,1; jne fail; fallthrough
        let begin = 0x1000u64;
        let bytes = hex("0fb774243885f6740a83fe01750590909090");
        let groups = find_ifeq_tag_groups(None, begin, &bytes);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0][0].0, 0);
        assert_eq!(groups[0][1].0, 1);
    }

    #[test]
    fn condition_base_ifeq_union() {
        // movzx edi,[rsp+38]; test di,di; je tag0; cmp di,1; jne fail; fallthrough tag1
        let begin = 0x186d_21adeu64;
        let bytes = hex("0fb77c24386685ff0f847425a8006683ff010f85b425a800488b0b");
        let groups = find_ifeq_tag_groups(None, begin, &bytes);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0][0], (0, 0x1877_a4060));
        assert_eq!(groups[0][1], (1, 0x186d_21af6));
    }

    #[test]
    fn interactive_inline_member_count_is_25() {
        let bytes = hex(
            "0fb6288b5f3083eb010f88c42bc50148ff4750ff4740ff4744895f304080fdff0f842b0700004c897424400f2974242048833e000f84b32bc5014080fd19",
        );
        assert_eq!(find_inline_member_count(&bytes), Some(0x19));
    }

    #[test]
    fn interactive_template_variant_member_count_is_14_after_alloc() {
        // movzx ebp, [rax]; ... alloc ... cmp bpl, 0xFF; ... cmp bpl, 0x0E (102 bytes later)
        let prefix = hex("0fb628");
        let pad = vec![0x90u8; 100];
        let suffix = hex("4080fdff9090904080fd0e");
        let mut bytes = prefix;
        bytes.extend(pad);
        bytes.extend(suffix);
        assert_eq!(find_inline_member_count(&bytes), Some(0x0E));
    }

    #[test]
    fn optional_struct_memcpy_counts_8_and_2() {
        // add [rdi+0x50], 8 (REX.W) then add [rdi+0x50], 2
        let bytes = hex("488347500883475002");
        let counts = find_struct_memcpy_counts(&bytes);
        assert_eq!(counts.get(&8).copied(), Some(1));
        assert_eq!(counts.get(&2).copied(), Some(1));
    }

    #[test]
    fn mov_edx_16_is_optional_vector3_width() {
        assert_eq!(match_mov_imm_2_8_16(&hex("ba10000000")), Some((16, 5)));
        assert_eq!(match_mov_imm_2_8_16(&hex("b208")), Some((8, 2)));
    }

    #[test]
    fn readunmanaged_helper_advances_reader_by_edx() {
        // test edx,edx; ... add [rbx+0x50], rdi
        let bytes = hex("85d2743c48895c2410574883ec204863fa488bd98b71302bf748017b50");
        assert!(callee_has_reader_advance(&bytes));
    }

    #[test]
    fn fkeyframe_array_reader_is_memcpy_stride_32() {
        // cmp [rbx+0x30], 4; ... cmp edi, -1; shl r14d, 5
        let bytes = hex("837b300483ffff448bf741c1e605443b7330");
        assert_eq!(find_unmanaged_array_stride(&bytes), Some(32));
    }

    #[test]
    fn gameplay_tag_array_reader_is_memcpy_stride_4() {
        // cmp [rbx+0x30], 4; cmp edi, -1; lea r14d, [rdi*4]
        let bytes = hex("837b300483ffffff448d34bd00000000");
        assert_eq!(find_unmanaged_array_stride(&bytes), Some(4));
    }

    #[test]
    fn gameplay_tag_lea_past_192_is_still_stride_4() {
        // Native helper 0x1860ecb10: remaining/null checks in the first 192,
        // `lea r14d, [rdi*4]` at +0xe3.
        let mut bytes = hex("837b300483ffffff");
        bytes.resize(0xe3, 0x90);
        bytes.extend(hex("448d34bd00000000"));
        let strides = find_all_unmanaged_array_strides(&bytes);
        assert!(strides.contains(&4), "{strides:?}");
    }

    #[test]
    fn gameplay_tag_imul_4_near_cmp_neg1_is_stride_4() {
        // cmp edi, -1; imul r14d, edi, 4
        let bytes = hex("83ffffff446bf604");
        let strides = find_all_unmanaged_array_strides(&bytes);
        assert!(strides.contains(&4), "{strides:?}");
    }

    #[test]
    fn shader_config_inline_member_count_is_1() {
        let bytes = hex("0fb67c24304080ff01");
        assert_eq!(find_inline_member_count(&bytes), Some(1));
    }

    #[test]
    fn decoder_map_omits_ambiguous_data_leaf() {
        let unions = vec![
            UnionTable {
                static_type: "Beyond.Gameplay.Core.AbilityActionData".into(),
                wrapper_type: "AbilityActionDataForMemoryPack".into(),
                formatter_type: "Fmt".into(),
                deserialize_va: "0x1".into(),
                max_tag: 1,
                jumptable_rva: "0x2".into(),
                tags: BTreeMap::from([("0".into(), "A".into()), ("1".into(), "B".into())]),
                evidence: vec![],
                skipped: vec![],
                status: "native_jumptable".into(),
            },
            UnionTable {
                static_type: "Beyond.Gameplay.Core.Selector+Finder+Data".into(),
                wrapper_type: "FinderDataForMemoryPack".into(),
                formatter_type: "Fmt2".into(),
                deserialize_va: "0x3".into(),
                max_tag: 1,
                jumptable_rva: "0x4".into(),
                tags: BTreeMap::from([
                    ("0".into(), "HitBoxFinder".into()),
                    ("1".into(), "OtherFinder".into()),
                ]),
                evidence: vec![],
                skipped: vec![],
                status: "native_jumptable".into(),
            },
            UnionTable {
                static_type: "Beyond.Gameplay.Core.Selector+Validator+Data".into(),
                wrapper_type: "ValidatorDataForMemoryPack".into(),
                formatter_type: "Fmt3".into(),
                deserialize_va: "0x5".into(),
                max_tag: 1,
                jumptable_rva: "0x6".into(),
                tags: BTreeMap::from([("0".into(), "V0".into()), ("1".into(), "V1".into())]),
                evidence: vec![],
                skipped: vec![],
                status: "native_jumptable".into(),
            },
        ];
        let map = decoder_union_map(&unions);
        assert!(map.contains_key("Beyond.Gameplay.Core.AbilityActionData"));
        assert!(map.contains_key("AbilityActionData"));
        assert!(map.contains_key("Beyond.Gameplay.Core.Selector+Finder+Data"));
        assert!(map.contains_key("Finder+Data"));
        assert!(map.contains_key("Validator+Data"));
        assert!(!map.contains_key("Data"));
        assert_eq!(map["AbilityActionData"]["0"], "A");
        assert_eq!(
            map["Beyond.Gameplay.Core.Selector+Finder+Data"]["0"],
            "HitBoxFinder"
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
