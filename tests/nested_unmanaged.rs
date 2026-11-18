//! Synthetic export of nested unmanaged layouts.
//!
//! Proves the exporter closes instance-field dependencies of layouts it
//! already decided to emit. The fixture is hand-built metadata, not a game
//! dump: `ChainA -> ChainB -> ChainC`, and `BezierKnot -> float3 / quaternion
//! -> float4` with the field shapes previously measured for those value types.
//! `Unity.Mathematics.*` is not on any allow-list; it is reached only because
//! `List<BezierKnot>` is on the wire.

use beyond_schema_dumper::layout::UnmanagedLayout;
use beyond_schema_dumper::metadata::Metadata;
use beyond_schema_dumper::pe::{PeImage, SectionInfo};
use beyond_schema_dumper::reg::{locate_metadata_registration, LocateOptions};
use beyond_schema_dumper::schema::export_bundle;
use std::collections::{BTreeSet, HashMap};

const IMAGE_BASE: u64 = 0x1_8000_0000;
const SECTION_RVA: u64 = 0x1000;
const RAW_PTR: usize = 0x200;

const TD_FORMATTER: usize = 1;
const TD_WRAP_IFACE: usize = 2;
const TD_MARKER: usize = 3;
const TD_FIXTURE: usize = 4;
const TD_KNOT: usize = 5;
const TD_FLOAT3: usize = 6;
const TD_QUAT: usize = 7;
const TD_FLOAT4: usize = 8;
const TD_CHAIN_A: usize = 9;
const TD_CHAIN_B: usize = 10;
const TD_CHAIN_C: usize = 11;
const TD_SHAPE: usize = 12;
const TD_HOLDS: usize = 13;
const TD_GHOST: usize = 14;
const TD_CYCLE_A: usize = 15;
const TD_CYCLE_B: usize = 16;
const TD_SELF: usize = 17;
const TD_TARGET_ONLY: usize = 18;
const TD_STATIC_PAYLOAD: usize = 19;
const TD_ORPHAN: usize = 20;
const TD_VECTOR3: usize = 21;
const TD_VECTOR4: usize = 22;
const TD_COLOR: usize = 23;
const TD_LIST: usize = 24;
const TD_COUNT: usize = 25;

const TY_VOID: i32 = 0;
const TY_FLOAT: i32 = 1;
const TY_INT: i32 = 2;
const TY_STRING: i32 = 3;
const TY_KNOT: i32 = 4;
const TY_FLOAT3: i32 = 5;
const TY_QUAT: i32 = 6;
const TY_FLOAT4: i32 = 7;
const TY_CHAIN_A: i32 = 8;
const TY_CHAIN_B: i32 = 9;
const TY_CHAIN_C: i32 = 10;
const TY_CHAIN_C_REF: i32 = 11;
const TY_SHAPE: i32 = 12;
const TY_HOLDS: i32 = 13;
const TY_GHOST: i32 = 14;
const TY_CYCLE_A: i32 = 15;
const TY_CYCLE_B: i32 = 16;
const TY_SELF: i32 = 17;
const TY_TARGET_ONLY: i32 = 18;
const TY_STATIC: i32 = 19;
const TY_ORPHAN: i32 = 20;
const TY_VECTOR3: i32 = 21;
const TY_VECTOR4: i32 = 22;
const TY_COLOR: i32 = 23;
const TY_FIXTURE: i32 = 24;
const TY_MARKER: i32 = 25;
const TY_WRAP_DEF: i32 = 26;
const TY_LIST_DEF: i32 = 27;
const TY_LIST_KNOT: i32 = 28;
const TY_WRAP_INST: i32 = 29;
const TY_CHAIN_A_ARRAY: i32 = 30;
const TY_COUNT: usize = 31;

const VALUETYPE: u32 = 1;
const ENUMTYPE: u32 = 2;
const BLITTABLE: u32 = 1 << 4;
const PUBLIC: u32 = 0x0006;
const STATIC_PUBLIC: u32 = 0x0016;

#[test]
fn closes_nested_unmanaged_dependencies() {
    let meta_bytes = build_metadata();
    let meta = Metadata::parse(meta_bytes).expect("parse synthetic metadata");
    assert_eq!(meta.type_defs.len(), TD_COUNT);

    let pe = build_pe();
    let located = locate_metadata_registration(
        &pe,
        TD_COUNT as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: Some(SECTION_RVA),
        },
    )
    .expect("known rva");
    assert_eq!(located.source, "known-rva");

    let bundle = export_bundle(&meta, &pe, &located.reg, located.source).expect("export");
    let again = export_bundle(&meta, &pe, &located.reg, located.source).expect("export again");
    assert_eq!(
        serde_json::to_string(&bundle.unmanaged).unwrap(),
        serde_json::to_string(&again.unmanaged).unwrap(),
        "unmanaged export must be stable across runs"
    );

    let names: Vec<&str> = bundle
        .unmanaged
        .iter()
        .map(|layout| layout.type_name.as_str())
        .collect();
    assert!(
        names.windows(2).all(|pair| pair[0] < pair[1]),
        "unmanaged entries must be sorted, got {names:?}"
    );
    assert_eq!(
        names,
        vec![
            "Game.Nest.ChainA",
            "Game.Nest.ChainB",
            "Game.Nest.ChainC",
            "Unity.Mathematics.float3",
            "Unity.Mathematics.float4",
            "Unity.Mathematics.quaternion",
            "UnityEngine.Color",
            "UnityEngine.Splines.BezierKnot",
            "UnityEngine.Vector3",
            "UnityEngine.Vector4",
        ]
    );

    let doc = &bundle.schemas;
    assert_eq!(doc.counts.wrappers, 1);
    let wrapper = &doc.wrappers[0];
    assert_eq!(wrapper.target_type.as_deref(), Some("Game.Fixture"));
    let wire: Vec<(&str, &str)> = wrapper
        .wire_order
        .iter()
        .map(|member| (member.name.as_str(), member.ty.as_str()))
        .collect();
    assert_eq!(
        wire,
        vec![
            (
                "knots",
                "System.Collections.Generic.List`1<UnityEngine.Splines.BezierKnot>"
            ),
            ("chain", "Game.Nest.ChainA[]"),
            ("bad", "Game.Nest.HoldsRef"),
            ("cycle", "Game.Nest.CycleA"),
            ("selfRef", "Game.Nest.SelfRef"),
        ]
    );
    assert!(wrapper
        .members_from_target_fields
        .iter()
        .any(|field| field.name == "onlyOnTarget" && field.ty == "Game.Nest.TargetOnly"));
    assert!(wrapper
        .wire_order
        .iter()
        .all(|member| member.name != "onlyOnTarget" && !member.ty.contains("float3")));

    let knot = layout(&bundle.unmanaged, "UnityEngine.Splines.BezierKnot");
    assert!(knot.blittable);
    assert_eq!(knot.status, "il2cpp_native_valuetype");
    assert_eq!(
        (knot.payload_size, knot.native_size, knot.instance_size),
        (56, 56, 72)
    );
    assert_eq!(
        fields_of(knot),
        vec![
            ("Position", "Unity.Mathematics.float3", 0, 12),
            ("TangentIn", "Unity.Mathematics.float3", 12, 12),
            ("TangentOut", "Unity.Mathematics.float3", 24, 12),
            ("Rotation", "Unity.Mathematics.quaternion", 36, 16),
            ("Width", "float", 52, 4),
        ]
    );

    let float3 = layout(&bundle.unmanaged, "Unity.Mathematics.float3");
    assert!(float3.blittable);
    assert_eq!(
        (
            float3.payload_size,
            float3.native_size,
            float3.instance_size
        ),
        (12, 12, 28)
    );
    assert_eq!(
        fields_of(float3),
        vec![
            ("x", "float", 0, 4),
            ("y", "float", 4, 4),
            ("z", "float", 8, 4),
        ]
    );

    let float4 = layout(&bundle.unmanaged, "Unity.Mathematics.float4");
    assert!(float4.blittable);
    assert_eq!(
        (
            float4.payload_size,
            float4.native_size,
            float4.instance_size
        ),
        (16, 16, 32)
    );
    assert_eq!(
        fields_of(float4),
        vec![
            ("x", "float", 0, 4),
            ("y", "float", 4, 4),
            ("z", "float", 8, 4),
            ("w", "float", 12, 4),
        ]
    );

    let quaternion = layout(&bundle.unmanaged, "Unity.Mathematics.quaternion");
    assert!(quaternion.blittable);
    assert_eq!(
        (
            quaternion.payload_size,
            quaternion.native_size,
            quaternion.instance_size
        ),
        (16, 16, 32)
    );
    assert_eq!(
        fields_of(quaternion),
        vec![("value", "Unity.Mathematics.float4", 0, 16)]
    );

    let chain_a = layout(&bundle.unmanaged, "Game.Nest.ChainA");
    let chain_b = layout(&bundle.unmanaged, "Game.Nest.ChainB");
    let chain_c = layout(&bundle.unmanaged, "Game.Nest.ChainC");
    assert_eq!(fields_of(chain_a), vec![("head", "Game.Nest.ChainB", 0, 8)]);
    // Byref spelling stays on the field; the dependency key is the typedef name.
    assert_eq!(fields_of(chain_b), vec![("mid", "Game.Nest.ChainC&", 0, 8)]);
    assert_eq!(
        fields_of(chain_c),
        vec![("n", "float", 0, 4), ("kind", "Game.Nest.Shape", 4, 4)]
    );
    assert!(chain_a.blittable && chain_b.blittable && chain_c.blittable);
    assert_eq!(chain_c.payload_size, 8);

    let shape = bundle
        .enums
        .iter()
        .find(|item| item.type_name == "Game.Nest.Shape")
        .expect("enum layout");
    assert_eq!(shape.underlying, "int");
    assert_eq!(shape.width, 4);
    assert_eq!(shape.status, "metadata_value__");

    let vector3 = layout(&bundle.unmanaged, "UnityEngine.Vector3");
    assert!(vector3.blittable);
    assert_eq!(
        fields_of(vector3),
        vec![
            ("x", "float", 0, 4),
            ("y", "float", 4, 4),
            ("z", "float", 8, 4),
        ]
    );
    let vector4 = layout(&bundle.unmanaged, "UnityEngine.Vector4");
    let color = layout(&bundle.unmanaged, "UnityEngine.Color");
    assert!(!vector4.blittable && !color.blittable);
    assert_eq!(vector4.fields.len(), 2);
    assert_eq!(color.fields.len(), 2);
    assert_eq!(vector4.fields[0].ty, "UnityEngine.Color");
    assert_eq!(color.fields[0].ty, "UnityEngine.Vector4");

    let missing: BTreeSet<String> = bundle.missing["items"]
        .as_array()
        .expect("missing items")
        .iter()
        .map(|item| {
            assert_eq!(item["status"], "unresolved");
            assert_eq!(item["referenced_by"], "Game.Fixture");
            item["type"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(
        missing,
        BTreeSet::from([
            "Game.Nest.CycleA".to_string(),
            "Game.Nest.HoldsRef".to_string(),
            "Game.Nest.SelfRef".to_string(),
        ])
    );
}

fn layout<'a>(items: &'a [UnmanagedLayout], name: &str) -> &'a UnmanagedLayout {
    items
        .iter()
        .find(|item| item.type_name == name)
        .unwrap_or_else(|| panic!("unmanaged layout {name} was not exported"))
}

fn fields_of(layout: &UnmanagedLayout) -> Vec<(&str, &str, i32, i32)> {
    layout
        .fields
        .iter()
        .map(|field| {
            (
                field.name.as_str(),
                field.ty.as_str(),
                field.offset,
                field.size.expect("sized field"),
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
struct FieldSpec {
    name: &'static str,
    ty: i32,
    offset: i32,
}

fn add_fields(out: &mut [Vec<FieldSpec>], td: usize, fields: &[(&'static str, i32, i32)]) {
    out[td] = fields
        .iter()
        .map(|(name, ty, offset)| FieldSpec {
            name,
            ty: *ty,
            offset: *offset,
        })
        .collect();
}

fn specs() -> Vec<Vec<FieldSpec>> {
    let mut out = vec![Vec::new(); TD_COUNT];
    add_fields(
        &mut out,
        TD_FIXTURE,
        &[
            ("knots", TY_LIST_KNOT, 16),
            ("chain", TY_CHAIN_A_ARRAY, 24),
            ("bad", TY_HOLDS, 32),
            ("cycle", TY_CYCLE_A, 40),
            ("selfRef", TY_SELF, 48),
            ("onlyOnTarget", TY_TARGET_ONLY, 56),
        ],
    );
    add_fields(
        &mut out,
        TD_KNOT,
        &[
            ("Position", TY_FLOAT3, 0),
            ("TangentIn", TY_FLOAT3, 12),
            ("TangentOut", TY_FLOAT3, 24),
            ("Rotation", TY_QUAT, 36),
            ("Width", TY_FLOAT, 52),
            ("staticDefault", TY_STATIC, 0),
        ],
    );
    add_fields(
        &mut out,
        TD_FLOAT3,
        &[("x", TY_FLOAT, 0), ("y", TY_FLOAT, 4), ("z", TY_FLOAT, 8)],
    );
    add_fields(&mut out, TD_QUAT, &[("value", TY_FLOAT4, 0)]);
    add_fields(
        &mut out,
        TD_FLOAT4,
        &[
            ("x", TY_FLOAT, 0),
            ("y", TY_FLOAT, 4),
            ("z", TY_FLOAT, 8),
            ("w", TY_FLOAT, 12),
        ],
    );
    add_fields(&mut out, TD_CHAIN_A, &[("head", TY_CHAIN_B, 0)]);
    add_fields(&mut out, TD_CHAIN_B, &[("mid", TY_CHAIN_C_REF, 0)]);
    add_fields(
        &mut out,
        TD_CHAIN_C,
        &[("n", TY_FLOAT, 0), ("kind", TY_SHAPE, 4)],
    );
    add_fields(&mut out, TD_SHAPE, &[("value__", TY_INT, 0)]);
    add_fields(
        &mut out,
        TD_HOLDS,
        &[("label", TY_STRING, 0), ("ghost", TY_GHOST, 8)],
    );
    add_fields(&mut out, TD_GHOST, &[("g", TY_FLOAT, 0)]);
    add_fields(
        &mut out,
        TD_CYCLE_A,
        &[("other", TY_CYCLE_B, 0), ("n", TY_FLOAT, 8)],
    );
    add_fields(
        &mut out,
        TD_CYCLE_B,
        &[("other", TY_CYCLE_A, 0), ("n", TY_FLOAT, 8)],
    );
    add_fields(
        &mut out,
        TD_SELF,
        &[("inner", TY_SELF, 0), ("n", TY_FLOAT, 8)],
    );
    add_fields(&mut out, TD_TARGET_ONLY, &[("v", TY_FLOAT, 0)]);
    add_fields(&mut out, TD_STATIC_PAYLOAD, &[("s", TY_FLOAT, 0)]);
    add_fields(&mut out, TD_ORPHAN, &[("o", TY_FLOAT, 0)]);
    add_fields(
        &mut out,
        TD_VECTOR3,
        &[("x", TY_FLOAT, 0), ("y", TY_FLOAT, 4), ("z", TY_FLOAT, 8)],
    );
    add_fields(
        &mut out,
        TD_VECTOR4,
        &[("peer", TY_COLOR, 0), ("pad", TY_FLOAT, 16)],
    );
    add_fields(
        &mut out,
        TD_COLOR,
        &[("peer", TY_VECTOR4, 0), ("pad", TY_FLOAT, 16)],
    );
    out
}

fn sizes() -> Vec<(i32, i32)> {
    let mut out = vec![(0, 0); TD_COUNT];
    let set = |out: &mut Vec<(i32, i32)>, td: usize, instance: i32, native: i32| {
        out[td] = (instance, native);
    };
    set(&mut out, TD_KNOT, 72, 56);
    set(&mut out, TD_FLOAT3, 28, 12);
    set(&mut out, TD_QUAT, 32, 16);
    set(&mut out, TD_FLOAT4, 32, 16);
    set(&mut out, TD_CHAIN_A, 24, 8);
    set(&mut out, TD_CHAIN_B, 24, 8);
    set(&mut out, TD_CHAIN_C, 24, 8);
    set(&mut out, TD_SHAPE, 20, 4);
    set(&mut out, TD_HOLDS, 40, 16);
    set(&mut out, TD_GHOST, 20, 4);
    set(&mut out, TD_CYCLE_A, 32, 12);
    set(&mut out, TD_CYCLE_B, 32, 12);
    set(&mut out, TD_SELF, 32, 12);
    set(&mut out, TD_TARGET_ONLY, 20, 4);
    set(&mut out, TD_STATIC_PAYLOAD, 20, 4);
    set(&mut out, TD_ORPHAN, 20, 4);
    set(&mut out, TD_VECTOR3, 28, 12);
    set(&mut out, TD_VECTOR4, 36, 20);
    set(&mut out, TD_COLOR, 36, 20);
    out
}

fn build_pe() -> PeImage {
    let field_specs = specs();
    let type_sizes = sizes();
    let mut blob = Rdata::new(IMAGE_BASE + SECTION_RVA);
    let (reg_off, _) = blob.alloc(0x80);
    assert_eq!(reg_off, 0);

    let (types_off, types_va) = blob.alloc(TY_COUNT * 8);
    let mut type_offs = Vec::with_capacity(TY_COUNT);
    let mut type_vas = Vec::with_capacity(TY_COUNT);
    for _ in 0..TY_COUNT {
        let (off, va) = blob.alloc(12);
        type_offs.push(off);
        type_vas.push(va);
    }

    let (list_gclass_off, list_gclass_va) = blob.alloc(16);
    let (list_ginst_off, list_ginst_va) = blob.alloc(16);
    let (list_argv_off, list_argv_va) = blob.alloc(8);
    let (wrap_gclass_off, wrap_gclass_va) = blob.alloc(16);
    let (wrap_ginst_off, wrap_ginst_va) = blob.alloc(16);
    let (wrap_argv_off, wrap_argv_va) = blob.alloc(8);

    let (field_ptrs_off, field_ptrs_va) = blob.alloc(TD_COUNT * 8);
    for (ti, fields) in field_specs.iter().enumerate() {
        if fields.is_empty() {
            blob.set_u64(field_ptrs_off + ti * 8, 0);
            continue;
        }
        let (off, va) = blob.alloc(fields.len() * 4);
        for (index, field) in fields.iter().enumerate() {
            blob.set_i32(off + index * 4, field.offset);
        }
        blob.set_u64(field_ptrs_off + ti * 8, va);
    }

    let (size_ptrs_off, size_ptrs_va) = blob.alloc(TD_COUNT * 8);
    for (ti, (instance, native)) in type_sizes.iter().enumerate() {
        if *instance == 0 && *native == 0 {
            blob.set_u64(size_ptrs_off + ti * 8, 0);
            continue;
        }
        let (off, va) = blob.alloc(16);
        blob.set_i32(off, *instance);
        blob.set_i32(off + 4, *native);
        blob.set_u64(size_ptrs_off + ti * 8, va);
    }

    let vt = |td: i32| (td as u64, bits(17, PUBLIC));
    let class = |td: i32| (td as u64, bits(18, 0));
    let mut plain = vec![None; TY_COUNT];
    plain[TY_VOID as usize] = Some((0, bits(1, 0)));
    plain[TY_FLOAT as usize] = Some((0, bits(12, PUBLIC)));
    plain[TY_INT as usize] = Some((0, bits(8, PUBLIC)));
    plain[TY_STRING as usize] = Some((0, bits(14, PUBLIC)));
    plain[TY_KNOT as usize] = Some(vt(TD_KNOT as i32));
    plain[TY_FLOAT3 as usize] = Some(vt(TD_FLOAT3 as i32));
    plain[TY_QUAT as usize] = Some(vt(TD_QUAT as i32));
    plain[TY_FLOAT4 as usize] = Some(vt(TD_FLOAT4 as i32));
    plain[TY_CHAIN_A as usize] = Some(vt(TD_CHAIN_A as i32));
    plain[TY_CHAIN_B as usize] = Some(vt(TD_CHAIN_B as i32));
    plain[TY_CHAIN_C as usize] = Some(vt(TD_CHAIN_C as i32));
    plain[TY_CHAIN_C_REF as usize] = Some((TD_CHAIN_C as u64, bits_ref(17, PUBLIC)));
    plain[TY_SHAPE as usize] = Some((TD_SHAPE as u64, bits(0x55, PUBLIC)));
    plain[TY_HOLDS as usize] = Some(vt(TD_HOLDS as i32));
    plain[TY_GHOST as usize] = Some(vt(TD_GHOST as i32));
    plain[TY_CYCLE_A as usize] = Some(vt(TD_CYCLE_A as i32));
    plain[TY_CYCLE_B as usize] = Some(vt(TD_CYCLE_B as i32));
    plain[TY_SELF as usize] = Some(vt(TD_SELF as i32));
    plain[TY_TARGET_ONLY as usize] = Some(vt(TD_TARGET_ONLY as i32));
    plain[TY_STATIC as usize] = Some((TD_STATIC_PAYLOAD as u64, bits(17, STATIC_PUBLIC)));
    plain[TY_ORPHAN as usize] = Some(vt(TD_ORPHAN as i32));
    plain[TY_VECTOR3 as usize] = Some(vt(TD_VECTOR3 as i32));
    plain[TY_VECTOR4 as usize] = Some(vt(TD_VECTOR4 as i32));
    plain[TY_COLOR as usize] = Some(vt(TD_COLOR as i32));
    plain[TY_FIXTURE as usize] = Some(class(TD_FIXTURE as i32));
    plain[TY_MARKER as usize] = Some(class(TD_MARKER as i32));
    plain[TY_WRAP_DEF as usize] = Some(class(TD_WRAP_IFACE as i32));
    plain[TY_LIST_DEF as usize] = Some(class(TD_LIST as i32));
    for (index, slot) in plain.iter().enumerate() {
        if let Some((data, ty_bits)) = slot {
            write_ty(&mut blob, type_offs[index], *data, *ty_bits);
        }
    }
    write_ty(
        &mut blob,
        type_offs[TY_LIST_KNOT as usize],
        list_gclass_va,
        bits(21, 0),
    );
    write_ty(
        &mut blob,
        type_offs[TY_WRAP_INST as usize],
        wrap_gclass_va,
        bits(21, 0),
    );
    write_ty(
        &mut blob,
        type_offs[TY_CHAIN_A_ARRAY as usize],
        type_vas[TY_CHAIN_A as usize],
        bits(0x1d, PUBLIC),
    );

    blob.set_u64(list_gclass_off, type_vas[TY_LIST_DEF as usize]);
    blob.set_u64(list_gclass_off + 8, list_ginst_va);
    blob.set_u64(list_ginst_off, 1);
    blob.set_u64(list_ginst_off + 8, list_argv_va);
    blob.set_u64(list_argv_off, type_vas[TY_KNOT as usize]);

    blob.set_u64(wrap_gclass_off, type_vas[TY_WRAP_DEF as usize]);
    blob.set_u64(wrap_gclass_off + 8, wrap_ginst_va);
    blob.set_u64(wrap_ginst_off, 1);
    blob.set_u64(wrap_ginst_off + 8, wrap_argv_va);
    blob.set_u64(wrap_argv_off, type_vas[TY_FIXTURE as usize]);

    for (index, va) in type_vas.iter().enumerate() {
        blob.set_u64(types_off + index * 8, *va);
    }

    blob.set_u64(reg_off + 0x30, TY_COUNT as u64);
    blob.set_u64(reg_off + 0x38, types_va);
    blob.set_u64(reg_off + 0x50, TD_COUNT as u64);
    blob.set_u64(reg_off + 0x58, field_ptrs_va);
    blob.set_u64(reg_off + 0x60, TD_COUNT as u64);
    blob.set_u64(reg_off + 0x68, size_ptrs_va);

    let mut data = vec![0u8; RAW_PTR];
    data.extend_from_slice(&blob.buf);
    let raw_size = blob.buf.len() as u32;
    PeImage::from_parts(
        IMAGE_BASE,
        vec![SectionInfo {
            name: ".rdata".into(),
            virtual_address: SECTION_RVA as u32,
            virtual_size: raw_size,
            raw_ptr: RAW_PTR as u32,
            raw_size,
        }],
        data,
    )
}

fn bits(type_enum: u32, attrs: u32) -> u32 {
    (type_enum << 16) | (attrs & 0xffff)
}

fn bits_ref(type_enum: u32, attrs: u32) -> u32 {
    bits(type_enum, attrs) | (1 << 29)
}

fn write_ty(blob: &mut Rdata, off: usize, data: u64, bits: u32) {
    blob.set_u64(off, data);
    blob.set_u32(off + 8, bits);
}

struct Rdata {
    base: u64,
    buf: Vec<u8>,
}

impl Rdata {
    fn new(base: u64) -> Self {
        Self {
            base,
            buf: Vec::new(),
        }
    }

    fn alloc(&mut self, n: usize) -> (usize, u64) {
        while !self.buf.len().is_multiple_of(8) {
            self.buf.push(0);
        }
        let off = self.buf.len();
        self.buf.resize(off + n, 0);
        (off, self.base + off as u64)
    }

    fn set_u64(&mut self, off: usize, v: u64) {
        self.buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn set_u32(&mut self, off: usize, v: u32) {
        self.buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn set_i32(&mut self, off: usize, v: i32) {
        self.set_u32(off, v as u32);
    }
}

fn build_metadata() -> Vec<u8> {
    let mut strings = vec![0u8];
    let mut seen: HashMap<String, i32> = HashMap::new();
    let mut intern = |s: &str| -> i32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(index) = seen.get(s) {
            return *index;
        }
        let index = strings.len() as i32;
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
        seen.insert(s.to_string(), index);
        index
    };

    let s_mp_dll = intern("MemoryPack.Beyond.dll");
    let s_ns_mp = intern("Beyond.MemoryPack");
    let s_wrapper = intern("GameFixtureForMemoryPack");
    let s_fmt = intern("GameFixtureForMemoryPackFormatter");
    let s_wrap_iface = intern("IMemoryPackDeSerializeWrapper`1");
    let s_marker = intern("IMemoryPackSerialize");
    let s_game_dll = intern("Game.Fixture.dll");
    let s_game = intern("Game");
    let s_fixture = intern("Fixture");
    let s_splines = intern("UnityEngine.Splines");
    let s_knot = intern("BezierKnot");
    let s_math = intern("Unity.Mathematics");
    let s_float3 = intern("float3");
    let s_quat = intern("quaternion");
    let s_float4 = intern("float4");
    let s_nest = intern("Game.Nest");
    let s_chain_a = intern("ChainA");
    let s_chain_b = intern("ChainB");
    let s_chain_c = intern("ChainC");
    let s_shape = intern("Shape");
    let s_holds = intern("HoldsRef");
    let s_ghost = intern("Ghost");
    let s_cycle_a = intern("CycleA");
    let s_cycle_b = intern("CycleB");
    let s_self = intern("SelfRef");
    let s_target_only = intern("TargetOnly");
    let s_static = intern("StaticPayload");
    let s_orphan = intern("Orphan");
    let s_unity = intern("UnityEngine");
    let s_vector3 = intern("Vector3");
    let s_vector4 = intern("Vector4");
    let s_color = intern("Color");
    let s_core = intern("System.Private.CoreLib.dll");
    let s_generic_ns = intern("System.Collections.Generic");
    let s_list = intern("List`1");

    let s_inst = intern("__instance__");
    let s_pknots = intern("__knots__");
    let s_pchain = intern("__chain__");
    let s_pbad = intern("__bad__");
    let s_pcycle = intern("__cycle__");
    let s_pself = intern("__selfRef__");
    let s_set_knots = intern("set_knots");
    let s_set_chain = intern("set_chain");
    let s_set_bad = intern("set_bad");
    let s_set_cycle = intern("set_cycle");
    let s_set_self = intern("set_selfRef");
    let s_deser = intern("Deserialize");
    let s_regf = intern("RegisterFormatter");

    let mut names = HashMap::new();
    for (label, index) in [
        ("Position", intern("Position")),
        ("TangentIn", intern("TangentIn")),
        ("TangentOut", intern("TangentOut")),
        ("Rotation", intern("Rotation")),
        ("Width", intern("Width")),
        ("staticDefault", intern("staticDefault")),
        ("x", intern("x")),
        ("y", intern("y")),
        ("z", intern("z")),
        ("w", intern("w")),
        ("value", intern("value")),
        ("head", intern("head")),
        ("mid", intern("mid")),
        ("n", intern("n")),
        ("kind", intern("kind")),
        ("value__", intern("value__")),
        ("label", intern("label")),
        ("ghost", intern("ghost")),
        ("g", intern("g")),
        ("other", intern("other")),
        ("inner", intern("inner")),
        ("v", intern("v")),
        ("s", intern("s")),
        ("o", intern("o")),
        ("peer", intern("peer")),
        ("pad", intern("pad")),
        ("knots", intern("knots")),
        ("chain", intern("chain")),
        ("bad", intern("bad")),
        ("cycle", intern("cycle")),
        ("selfRef", intern("selfRef")),
        ("onlyOnTarget", intern("onlyOnTarget")),
    ] {
        names.insert(label, index);
    }

    let images = [
        image(s_mp_dll, 0, 4),
        image(s_game_dll, 4, 20),
        image(s_core, 24, 1),
    ]
    .concat();

    let blit = VALUETYPE | BLITTABLE;
    let enum_bits = VALUETYPE | ENUMTYPE;
    let field_specs = specs();
    let mut field_cursor = 0i32;
    let mut field_index_of = [-1i32; TD_COUNT];
    let mut field_count_of = [0u16; TD_COUNT];
    for (ti, fields) in field_specs.iter().enumerate() {
        if fields.is_empty() {
            continue;
        }
        field_index_of[ti] = field_cursor;
        field_count_of[ti] = fields.len() as u16;
        field_cursor += fields.len() as i32;
    }

    let mut typedefs = Vec::new();
    let push_td = |typedefs: &mut Vec<u8>, td: Td| {
        typedefs.extend(typedef(td));
    };
    push_td(
        &mut typedefs,
        Td {
            name: s_wrapper,
            ns: s_ns_mp,
            method_index: 0,
            method_count: 7,
            property_index: 0,
            property_count: 6,
            nested_type_index: 0,
            nested_type_count: 1,
            interfaces_index: 0,
            interfaces_count: 1,
            ..Td::default()
        },
    );
    push_td(
        &mut typedefs,
        Td {
            name: s_fmt,
            ..Td::default()
        },
    );
    push_td(
        &mut typedefs,
        Td {
            name: s_wrap_iface,
            ns: s_ns_mp,
            ..Td::default()
        },
    );
    push_td(
        &mut typedefs,
        Td {
            name: s_marker,
            ns: s_ns_mp,
            ..Td::default()
        },
    );
    push_td(
        &mut typedefs,
        Td {
            name: s_fixture,
            ns: s_game,
            field_index: field_index_of[TD_FIXTURE],
            field_count: field_count_of[TD_FIXTURE],
            interfaces_index: 1,
            interfaces_count: 1,
            ..Td::default()
        },
    );
    let valuetype = |name, ns, td_index, bits| Td {
        name,
        ns,
        field_index: field_index_of[td_index],
        field_count: field_count_of[td_index],
        bitfield: bits,
        ..Td::default()
    };
    for (name, ns, index, bits) in [
        (s_knot, s_splines, TD_KNOT, blit),
        (s_float3, s_math, TD_FLOAT3, blit),
        (s_quat, s_math, TD_QUAT, blit),
        (s_float4, s_math, TD_FLOAT4, blit),
        (s_chain_a, s_nest, TD_CHAIN_A, blit),
        (s_chain_b, s_nest, TD_CHAIN_B, blit),
        (s_chain_c, s_nest, TD_CHAIN_C, blit),
        (s_shape, s_nest, TD_SHAPE, enum_bits),
        (s_holds, s_nest, TD_HOLDS, VALUETYPE),
        (s_ghost, s_nest, TD_GHOST, blit),
        (s_cycle_a, s_nest, TD_CYCLE_A, VALUETYPE),
        (s_cycle_b, s_nest, TD_CYCLE_B, VALUETYPE),
        (s_self, s_nest, TD_SELF, VALUETYPE),
        (s_target_only, s_nest, TD_TARGET_ONLY, blit),
        (s_static, s_nest, TD_STATIC_PAYLOAD, blit),
        (s_orphan, s_nest, TD_ORPHAN, blit),
        (s_vector3, s_unity, TD_VECTOR3, blit),
        (s_vector4, s_unity, TD_VECTOR4, VALUETYPE),
        (s_color, s_unity, TD_COLOR, VALUETYPE),
    ] {
        push_td(&mut typedefs, valuetype(name, ns, index, bits));
    }
    push_td(
        &mut typedefs,
        Td {
            name: s_list,
            ns: s_generic_ns,
            ..Td::default()
        },
    );
    assert_eq!(typedefs.len(), TD_COUNT * 0x5c);

    let methods = [
        method(s_set_knots, 0, 0, 1),
        method(s_set_chain, 0, 1, 1),
        method(s_set_bad, 0, 2, 1),
        method(s_set_cycle, 0, 3, 1),
        method(s_set_self, 0, 4, 1),
        method(s_deser, 0, -1, 0),
        method(s_regf, 0, -1, 0),
    ]
    .concat();
    let parameters = [
        param(TY_LIST_KNOT),
        param(TY_CHAIN_A_ARRAY),
        param(TY_HOLDS),
        param(TY_CYCLE_A),
        param(TY_SELF),
    ]
    .concat();
    let properties = [
        prop(s_inst, -1, -1),
        prop(s_pknots, -1, 0),
        prop(s_pchain, -1, 1),
        prop(s_pbad, -1, 2),
        prop(s_pcycle, -1, 3),
        prop(s_pself, -1, 4),
    ]
    .concat();
    let mut fields = Vec::new();
    for group in &field_specs {
        for field in group {
            let name = names[field.name];
            fields.extend(field_def(name, field.ty));
        }
    }
    let nested = i32s(&[TD_FORMATTER as i32]);
    let interfaces = i32s(&[TY_WRAP_INST, TY_MARKER]);

    let mut file = vec![0u8; 0x110];
    file[0..4].copy_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
    file[4..8].copy_from_slice(&29i32.to_le_bytes());

    let string_off = file.len() as i32;
    let string_size = strings.len() as i32;
    file.extend_from_slice(&strings);

    let (images_off, images_size) = append(&mut file, &images);
    let (td_off, td_size) = append(&mut file, &typedefs);
    let (methods_off, methods_size) = append(&mut file, &methods);
    let (params_off, params_size) = append(&mut file, &parameters);
    let (props_off, props_size) = append(&mut file, &properties);
    let (fields_off, fields_size) = append(&mut file, &fields);
    let (nested_off, nested_size) = append(&mut file, &nested);
    let (ifaces_off, ifaces_size) = append(&mut file, &interfaces);

    put_section(&mut file, 0, 0x110, 0);
    put_section(&mut file, 2, string_off, string_size);
    put_section(&mut file, 4, props_off, props_size);
    put_section(&mut file, 5, methods_off, methods_size);
    put_section(&mut file, 10, params_off, params_size);
    put_section(&mut file, 11, fields_off, fields_size);
    put_section(&mut file, 15, nested_off, nested_size);
    put_section(&mut file, 16, ifaces_off, ifaces_size);
    put_section(&mut file, 19, td_off, td_size);
    put_section(&mut file, 20, images_off, images_size);
    for idx in [
        1, 3, 6, 7, 8, 9, 12, 13, 14, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ] {
        put_section(&mut file, idx, 0x110, 0);
    }
    file
}

fn append(file: &mut Vec<u8>, bytes: &[u8]) -> (i32, i32) {
    let off = file.len() as i32;
    file.extend_from_slice(bytes);
    (off, bytes.len() as i32)
}

fn put_section(header: &mut [u8], index: usize, off: i32, size: i32) {
    let at = 8 + index * 8;
    header[at..at + 4].copy_from_slice(&off.to_le_bytes());
    header[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
}

fn i32s(vals: &[i32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn image(name: i32, type_start: i32, type_count: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 0x28];
    put_i32(&mut buf, 0, name);
    put_i32(&mut buf, 8, type_start);
    put_u32(&mut buf, 12, type_count);
    buf
}

#[derive(Clone, Copy)]
struct Td {
    name: i32,
    ns: i32,
    field_index: i32,
    method_index: i32,
    property_index: i32,
    nested_type_index: i32,
    interfaces_index: i32,
    method_count: u16,
    property_count: u16,
    field_count: u16,
    nested_type_count: u16,
    interfaces_count: u16,
    bitfield: u32,
}

impl Default for Td {
    fn default() -> Self {
        Self {
            name: 0,
            ns: 0,
            field_index: -1,
            method_index: -1,
            property_index: -1,
            nested_type_index: -1,
            interfaces_index: -1,
            method_count: 0,
            property_count: 0,
            field_count: 0,
            nested_type_count: 0,
            interfaces_count: 0,
            bitfield: 0,
        }
    }
}

fn typedef(td: Td) -> Vec<u8> {
    let mut buf = vec![0u8; 0x5c];
    put_i32(&mut buf, 0x00, td.name);
    put_i32(&mut buf, 0x04, td.ns);
    put_i32(&mut buf, 0x08, -1);
    put_i32(&mut buf, 0x0c, -1);
    put_i32(&mut buf, 0x10, -1);
    put_i32(&mut buf, 0x14, -1);
    put_i32(&mut buf, 0x18, -1);
    put_i32(&mut buf, 0x20, td.field_index);
    put_i32(&mut buf, 0x24, td.method_index);
    put_i32(&mut buf, 0x28, -1);
    put_i32(&mut buf, 0x2c, td.property_index);
    put_i32(&mut buf, 0x30, td.nested_type_index);
    put_i32(&mut buf, 0x34, td.interfaces_index);
    put_i32(&mut buf, 0x38, -1);
    put_i32(&mut buf, 0x3c, -1);
    put_u16(&mut buf, 0x44, td.method_count);
    put_u16(&mut buf, 0x46, td.property_count);
    put_u16(&mut buf, 0x48, td.field_count);
    put_u16(&mut buf, 0x4c, td.nested_type_count);
    put_u16(&mut buf, 0x50, td.interfaces_count);
    put_u32(&mut buf, 0x54, td.bitfield);
    buf
}

fn method(name: i32, ret: i32, param_start: i32, param_count: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 0x20];
    put_i32(&mut buf, 0x00, name);
    put_i32(&mut buf, 0x04, 0);
    put_i32(&mut buf, 0x08, ret);
    put_i32(&mut buf, 0x0c, param_start);
    put_i32(&mut buf, 0x10, -1);
    put_u16(&mut buf, 0x1e, param_count);
    buf
}

fn param(type_index: i32) -> Vec<u8> {
    let mut buf = vec![0u8; 0x0c];
    put_i32(&mut buf, 8, type_index);
    buf
}

fn prop(name: i32, get: i32, set: i32) -> Vec<u8> {
    let mut buf = vec![0u8; 0x14];
    put_i32(&mut buf, 0, name);
    put_i32(&mut buf, 4, get);
    put_i32(&mut buf, 8, set);
    buf
}

fn field_def(name: i32, type_index: i32) -> Vec<u8> {
    let mut buf = vec![0u8; 0x0c];
    put_i32(&mut buf, 0, name);
    put_i32(&mut buf, 4, type_index);
    buf
}

fn put_i32(buf: &mut [u8], off: usize, v: i32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
