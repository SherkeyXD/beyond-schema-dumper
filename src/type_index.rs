use crate::layout::TypeLayouts;
use crate::schema::{MarkerSchema, WrapperSchema};
use crate::wire::{self, basename_of};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub fn build_type_index(
    wrappers: &[WrapperSchema],
    markers: &[MarkerSchema],
    layouts: &TypeLayouts,
) -> Value {
    let marker_types: HashSet<&str> = markers.iter().map(|m| m.type_name.as_str()).collect();
    let targets: HashSet<&str> = wrappers
        .iter()
        .filter_map(|w| w.target_type.as_deref())
        .collect();

    let mut by_type: BTreeMap<String, Vec<&WrapperSchema>> = BTreeMap::new();
    for w in wrappers {
        let Some(target) = w.target_type.as_ref() else {
            continue;
        };
        by_type.entry(target.clone()).or_default().push(w);
    }

    let mut by_type_json = Map::new();
    for (target, group) in &by_type {
        let entries: Vec<Value> = group
            .iter()
            .map(|w| {
                let wire: Vec<Value> = w
                    .wire_order
                    .iter()
                    .map(|m| {
                        let mut kind = wire::classify(&m.ty).label().to_string();
                        if kind == "named" {
                            kind = if layouts.unmanaged.contains_key(&m.ty) {
                                "unmanaged".into()
                            } else if layouts.enums.contains_key(&m.ty) {
                                "enum".into()
                            } else if targets.contains(m.ty.as_str()) {
                                "object".into()
                            } else if m.ty.contains("SerializeFieldDictionary") {
                                "dictionary_v2".into()
                            } else {
                                "unresolved".into()
                            };
                        }
                        json!({
                            "name": m.name,
                            "type": m.ty,
                            "kind": kind,
                        })
                    })
                    .collect();
                json!({
                    "wrapper_type": w.wrapper_type,
                    "typedef_index": w.typedef_index,
                    "target_typedef_index": w.target_typedef_index,
                    "assembly": w.assembly,
                    "target_assembly": w.target_assembly,
                    "orders_differ": w.orders_differ,
                    "has_formatter": w.has_formatter,
                    "formatter_type": w.formatter_type,
                    "wire": wire,
                })
            })
            .collect();
        by_type_json.insert(
            target.clone(),
            json!({
                "serialize_marker": marker_types.contains(target.as_str()),
                "entries": entries,
            }),
        );
    }

    let mut by_base: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for target in by_type.keys() {
        by_base
            .entry(basename_of(target))
            .or_default()
            .insert(target.clone());
    }
    let mut by_basename = Map::new();
    for (base, set) in by_base {
        let mut names: Vec<&String> = set.iter().collect();
        names.sort_by(|a, b| {
            let am = marker_types.contains(a.as_str());
            let bm = marker_types.contains(b.as_str());
            bm.cmp(&am).then(a.cmp(b))
        });
        by_basename.insert(base, json!(names));
    }

    json!({
        "generated_by": "beyond-schema-dumper",
        "usage": "When deserializing VFS JsonData, map Data/Json/**/{Basename}.json to by_basename[Basename]. Each string is a key in by_type. Prefer serialize_marker=true when several entries match. Deserialize with entries[].wire (wire_order), not target field declaration order. kind=string is a Beyond StringPool int32.",
        "identity": {
            "file_basename": "by_basename[file stem]. If missing and the stem ends with Table, try {stem minus Table}DataTable.",
            "path_segments": "Each JsonData folder name is tried as a basename, then {folder}Data and {folder}Json (SpawnerConfig→SpawnerConfigData, AnimationConfig→AnimationConfigJson).",
            "path_tokens": "If several types remain, pick the unique type whose wire length equals the root object header and whose name tokens overlap the JsonData path. Ignore stopwords data/json/config/table/system. Prefer serialize_marker.",
            "polymorphic_base": "A wrapper with has_deserialize=false and derived wrappers (parent_type / is_union_base) is polymorphic. The payload is either a union tag then the unique child memberCount, or the child object header alone.",
            "hashset": "System.Collections.Generic.HashSet`1<T> uses the same int32-count layout as List`1<T>."
        },
        "by_type": Value::Object(by_type_json),
        "by_basename": Value::Object(by_basename),
    })
}
