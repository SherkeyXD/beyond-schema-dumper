//! Dump instance-size table + Deserialize bodies for unmanaged candidates.
//! Run: cargo test -p beyond-schema-dumper --test inspect_game -- --ignored --nocapture

use beyond_schema_dumper::codegen::load_code_map;
use beyond_schema_dumper::layout::{is_blittable, is_enumtype, is_valuetype, load_instance_sizes};
use beyond_schema_dumper::metadata::Metadata;
use beyond_schema_dumper::pe::PeImage;
use beyond_schema_dumper::reg::{locate_metadata_registration, LocateOptions};
use beyond_schema_dumper::typesys::TypeSystem;

const META: &str =
    "/Users/sunyinzhen.325/Downloads/mmp/game-handoff/game/Metadata/global-metadata.dat";
const GA: &str = "/Users/sunyinzhen.325/Downloads/mmp/game-handoff/game/GameAssembly.dll";

const NAMES: &[&str] = &[
    "Beyond.AABB",
    "UnityEngine.Vector3",
    "Beyond.Gameplay.Core.GameplayTag",
    "Beyond.Resource.ManifestData+GUIDProxy",
    "Beyond.Gameplay.Core.DispelConfig",
    "Beyond.Gameplay.Core.BuffIconConfig+OrderPriorityConfig",
    "Beyond.Montage.AnimationClipAsyncInfo",
    "Beyond.Montage.FMontageTransitionInfo",
    "Beyond.NPC.Animation.AnimClipInfo",
    "Beyond.Gameplay.Core.ModelViewStateController.ConditionValue",
    "Beyond.Gameplay.Audio.Utils.AudioBlackScreenBehaviour",
    "Beyond.Resource.StringPathHash",
    "Beyond.Gameplay.Core.LevelScriptPtr",
    "Beyond.Gameplay.Core.AirWallPtr",
];

#[test]
#[ignore]
fn dump_size_table_only() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let n = located.reg.type_definitions_sizes_count as usize;
    let ptrs = pe
        .read_u64_array_va(located.reg.type_definitions_sizes, n)
        .expect("size ptrs");
    let ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    for want in NAMES {
        for (ti, _) in meta.type_defs.iter().enumerate() {
            let name = ts.typedef_full_name(ti as i32);
            if &name != want {
                continue;
            }
            let p = ptrs.get(ti).copied().unwrap_or(0);
            let inst = pe.read_i32_va(p).unwrap_or(-1);
            let native = pe.read_i32_va(p + 4).unwrap_or(-1);
            let statics = pe.read_u32_va(p + 8).unwrap_or(0);
            println!(
                "{name} td={ti} instance_size={inst} native_size={native} static_fields={statics}"
            );
        }
    }
}

#[test]
#[ignore]
fn dump_unmanaged_candidates() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let sizes_va = located.reg.type_definitions_sizes;
    println!(
        "type_definitions_sizes va={sizes_va:#x} count={}",
        located.reg.type_definitions_sizes_count
    );
    for i in 0..4u64 {
        let slot = pe.read_u64_va(sizes_va + i * 8);
        println!("  ptr[{i}]={slot:?}");
        if let Some(p) = slot {
            println!(
                "    packed-as-i32={:?} deref-i32={:?}",
                pe.read_i32_va(sizes_va + i * 16),
                pe.read_i32_va(p)
            );
        }
    }

    let packed: Vec<i32> = (0..8)
        .filter_map(|i| pe.read_i32_va(sizes_va + i * 16))
        .collect();
    println!("first packed i32s: {packed:?}");

    let instance_size = load_instance_sizes(&pe, &located.reg);
    let positive = instance_size.iter().filter(|s| **s > 0).count();
    println!(
        "load_instance_sizes positive={positive}/{}",
        instance_size.len()
    );

    let mut ts =
        TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");

    for want in NAMES {
        let mut hit = false;
        for (ti, td) in meta.type_defs.iter().enumerate() {
            let name = ts.typedef_full_name(ti as i32);
            if &name != want {
                continue;
            }
            hit = true;
            let sz = instance_size.get(ti).copied().unwrap_or(0);
            println!(
                "\n{name} td={ti} valuetype={} enum={} blittable={} flags={:#x} bitfield={:#x} instance_size={sz} fields={}",
                is_valuetype(td),
                is_enumtype(td),
                is_blittable(td),
                td.flags,
                td.bitfield,
                td.field_count
            );
            if td.field_count > 0 && td.field_index >= 0 {
                let start = td.field_index as usize;
                for local in 0..td.field_count as usize {
                    let Some(f) = meta.fields.get(start + local) else {
                        break;
                    };
                    let fname = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
                    let ty = ts.name_of_index(f.type_index);
                    println!("    field {fname}: {ty}");
                }
            }
            for m in code
                .methods
                .iter()
                .filter(|m| m.typedef_index == ti && m.name == "Deserialize")
            {
                let n = 96.min(
                    pe.data
                        .len()
                        .saturating_sub(pe.va_to_offset(m.va).unwrap_or(0)),
                );
                if let Some(off) = pe.va_to_offset(m.va) {
                    println!(
                        "  Deserialize va={:#x} {}",
                        m.va,
                        hex(&pe.data[off..off + n])
                    );
                }
            }
        }
        if !hit {
            println!("\nMISSING {want}");
        }
    }

    let wrappers = [
        "Beyond.MemoryPack.Beyond_NPC_Animation_AnimClipInfoForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_Core_BuffIconConfigForMemoryPack",
        "Beyond.MemoryPack.Beyond_Montage_NPCMontageJsonForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_Core_BuffDataForMemoryPack",
        "Beyond.MemoryPack.Beyond_AABBForMemoryPack",
        "Beyond.MemoryPack.Beyond_Resource_ManifestData_GUIDProxyForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_Core_GameplayTagForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_Core_DispelConfigForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_Core_BuffIconConfig_OrderPriorityConfigForMemoryPack",
        "Beyond.MemoryPack.Beyond_Montage_AnimationClipAsyncInfoForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_Core_LevelScriptPtrForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_Actions_Param_1_Beyond_Gameplay_Core_LevelScriptPtr_ForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_LevelEntityDataForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_LevelEnemyDataForMemoryPack",
        "Beyond.MemoryPack.Beyond_Gameplay_LevelInteractiveDataForMemoryPack",
    ];
    println!("\n=== wrapper Deserialize ===");
    for want in wrappers {
        let mut hit = false;
        for m in code
            .methods
            .iter()
            .filter(|m| m.declaring_name == want && m.name == "Deserialize")
        {
            hit = true;
            let n = 128.min(
                pe.data
                    .len()
                    .saturating_sub(pe.va_to_offset(m.va).unwrap_or(0)),
            );
            if let Some(off) = pe.va_to_offset(m.va) {
                println!("{want} va={:#x}\n  {}", m.va, hex(&pe.data[off..off + n]));
            }
        }
        if !hit {
            println!("NO Deserialize {want}");
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

const FAIL_NAMES: &[&str] = &[
    "Beyond.Gameplay.LevelInteractiveData",
    "Beyond.Gameplay.LevelEntityData",
    "Beyond.Gameplay.Core.Abilities.Condition.ConditionBase",
    "Beyond.Gameplay.Core.HealProcessorBase",
    "Beyond.Gameplay.Core.PoiseProcessorBase",
    "Beyond.Gameplay.View.Animation.AnimationConfigExtraData+AnimatedShaderPropertyConfig",
    "Beyond.Gameplay.View.Animation.AnimationConfigExtraData+ShaderPropertyEntry",
    "Beyond.Gameplay.View.Animation.AnimationConfigExtraData",
    "Beyond.Gameplay.View.Animation.EnemyAnimExtraData",
    "Beyond.Gameplay.View.Animation.CharacterAnimExtraData",
    "Beyond.Gameplay.View.Animation.UpperBodyFightExtraData",
    "Beyond.Gameplay.View.Animation.EnemyAnimExtraData+EnemyHurtAnimData",
    "Beyond.Gameplay.View.Animation.EnemyAnimExtraData+EnemyHurtAnimEntry",
    "Beyond.Gameplay.View.Animation.AnimationConfigJson",
    "Beyond.Gameplay.InteractiveTemplateData",
    "Beyond.Gameplay.Core.InteractiveTemplateVariant",
    "Beyond.Gameplay.Core.PropertyStateData",
    "Beyond.Gameplay.Core.BaseConditionData",
    "Beyond.FAnimationCurve",
    "Beyond.FKeyframe",
    "Beyond.Gameplay.Core.CharInteractPerform.BodyTypeActData",
    "Beyond.Gameplay.LevelSplineData",
    "Beyond.Gameplay.Core.EnableSpecialAim",
    "Beyond.Gameplay.Core.EnableSpecialAim+SpecialAimShapeEdit",
    "Beyond.Gameplay.Core.CharInteractPerform.CharInteractPerformRuntimeCfg",
    "Beyond.Gameplay.Core.CharInteractPerform.CharInteractPerformActionData",
    "Beyond.Gameplay.Core.CharInteractPerform.ActorActData",
    "Beyond.Gameplay.SpawnerActionData",
    "Beyond.Gameplay.SpawnerPreprocess+Data",
    "Beyond.UI.GPUI.PrefabGroupSerializeData",
    "Beyond.UI.GPUI.ExtendedPrefabGroupSerializeData",
    "Beyond.Gameplay.Actions.Param`1",
    "Beyond.Gameplay.LevelScriptData",
    "Beyond.Gameplay.LevelSplineData",
    "Beyond.Gameplay.AI.Config.NpcPatrolPoint",
];

#[test]
#[ignore]
fn dump_failing_deserialize() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let mut ts =
        TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");
    println!("methods={}", code.methods.len());

    let helpers = [
        ("object-header", 0x18C8_C5028u64),
        ("collection-header", 0x18C8_C4FC0),
        ("union-header", 0x18C8_C5074),
        ("bool", 0x18C8_C3A6C),
        ("beyond-string", 0x1851_F0F70),
        ("dictionary-v2", 0x185C_EA340),
        ("ReadObjectHeader-old", 0x184f_dfd70),
        ("ReadUInt32-old", 0x184f_df650),
    ];
    for (n, va) in helpers {
        println!("helper {n} {va:#x} mapped={}", pe.va_mapped(va));
    }

    for want in FAIL_NAMES {
        println!("\n===== {want} =====");
        let mut tds = Vec::new();
        for (ti, _) in meta.type_defs.iter().enumerate() {
            let name = ts.typedef_full_name(ti as i32);
            if &name == want || name.ends_with(want) {
                tds.push((ti, name));
            }
        }
        if tds.is_empty() {
            println!("  MISSING typedef");
            continue;
        }
        for (ti, name) in &tds {
            let td = &meta.type_defs[*ti];
            println!(
                "  td={ti} name={name} flags={:#x} fields={} methods={} parent_idx={}",
                td.flags, td.field_count, td.method_count, td.parent_index
            );
            if td.field_count > 0 && td.field_index >= 0 {
                let start = td.field_index as usize;
                for local in 0..td.field_count as usize {
                    let Some(f) = meta.fields.get(start + local) else {
                        break;
                    };
                    let fname = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
                    let ty = ts.name_of_index(f.type_index);
                    println!("    field {fname}: {ty}");
                }
            }
            for m in code.methods.iter().filter(|m| m.typedef_index == *ti) {
                if m.name == "Deserialize" || m.name == ".cctor" || m.name == "Serialize" {
                    dump_method(&pe, m);
                }
            }
        }
        let needle = want.replace(['.', '+', '`'], "_");
        for m in code.methods.iter().filter(|m| {
            m.declaring_name.contains(&needle) && (m.name == "Deserialize" || m.name == ".cctor")
        }) {
            dump_method(&pe, m);
        }
    }

    println!("\n===== empty-wire wrappers with Deserialize =====");
    let mut n = 0;
    for m in code.methods.iter().filter(|m| {
        m.name == "Deserialize"
            && m.declaring_name.contains("ForMemoryPack")
            && m.declaring_name.contains("Formatter")
    }) {
        let _ = m;
        n += 1;
    }
    println!("formatter Deserialize count={n}");
}

#[test]
#[ignore]
fn dump_send_lua_typeinfo_slots() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let mut ts =
        TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    println!(
        "methods={} type_ptrs={} method_specs={} metadata_usages={}",
        meta.methods.len(),
        ts.type_ptrs.len(),
        located.reg.method_specs_count,
        located.reg.metadata_usages_count
    );
    for (ti, td) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        if name != "Beyond.MemoryPack.Beyond_Gameplay_Actions_SendLuaEvent1ForMemoryPack"
            && name != "Beyond.Gameplay.Actions.SendLuaEvent1"
        {
            continue;
        }
        println!(
            "\n########## {name} td={ti} props={} fields={} ##########",
            td.property_count, td.field_count
        );
        if td.property_count > 0 && td.property_index >= 0 {
            let start = td.property_index as usize;
            for local in 0..td.property_count as usize {
                let Some(p) = meta.properties.get(start + local) else {
                    break;
                };
                let pname = meta.string(p.name_index).unwrap_or_else(|_| "?".into());
                let get = if (p.get as u32) < td.method_count as u32 && td.method_index >= 0 {
                    td.method_index.saturating_add(p.get)
                } else {
                    p.get
                };
                let set = if (p.set as u32) < td.method_count as u32 && td.method_index >= 0 {
                    td.method_index.saturating_add(p.set)
                } else {
                    p.set
                };
                let mut ty = "object".to_string();
                if get >= 0 {
                    if let Some(m) = meta.methods.get(get as usize) {
                        ty = ts.name_of_index(m.return_type);
                    }
                } else if set >= 0 {
                    if let Some(m) = meta.methods.get(set as usize) {
                        if m.parameter_count > 0 && m.parameter_start >= 0 {
                            if let Some(param) = meta.parameters.get(m.parameter_start as usize) {
                                ty = ts.name_of_index(param.type_index);
                            }
                        }
                    }
                }
                println!(
                    "  prop {pname} get={} set={} resolved_get={get} resolved_set={set} ty={ty}",
                    p.get, p.set
                );
            }
        }
    }
    for (name, slot) in [
        ("SendLuaEvent1 field5/scope?", 0x190775148u64),
        ("SendLuaEvent1 field9 extra", 0x1913eec38u64),
    ] {
        let enc = pe.read_u64_va(slot).unwrap_or(0);
        println!("{name} slot={slot:#x} enc={enc:#x} bit0={}", enc & 1);
        if enc & 1 == 0 {
            continue;
        }
        let usage = ((enc >> 29) & 7) as u32;
        let idx = ((enc >> 1) & 0x0FFF_FFFF) as i32;
        println!("  usage={usage} idx={idx}");
        match usage {
            1 => {
                if idx < 0 || idx as usize >= ts.type_ptrs.len() {
                    println!("  type_ptrs OOB {}", ts.type_ptrs.len());
                    continue;
                }
                let ty_va = ts.type_ptrs[idx as usize];
                let data = pe.read_u64_va(ty_va).unwrap_or(0);
                let td = data as i32;
                let tname = if td >= 0 && (td as usize) < meta.type_defs.len() {
                    ts.typedef_full_name(td)
                } else {
                    format!("td={td}")
                };
                println!("  TypeInfo ty_va={ty_va:#x} data={data:#x} {tname}");
            }
            3 if idx >= 0 && (idx as usize) < meta.methods.len() => {
                let m = &meta.methods[idx as usize];
                let decl = meta
                    .type_defs
                    .get(m.declaring_type as usize)
                    .map(|_td| ts.typedef_full_name(m.declaring_type))
                    .unwrap_or_else(|| "?".into());
                let mname = meta.string(m.name_index).unwrap_or_else(|_| "?".into());
                println!(
                    "  MethodDef {decl}::{mname} ret={}",
                    ts.name_of_index(m.return_type)
                );
            }
            6 if idx >= 0 && (idx as u64) < located.reg.method_specs_count => {
                let spec_va = located.reg.method_specs.wrapping_add((idx as u64) * 12);
                let method_i = pe.read_i32_va(spec_va).unwrap_or(-1);
                let class_i = pe.read_i32_va(spec_va + 4).unwrap_or(-1);
                let method_g = pe.read_i32_va(spec_va + 8).unwrap_or(-1);
                println!("  MethodSpec va={spec_va:#x} methodDef={method_i} classInst={class_i} methodInst={method_g}");
                if method_i >= 0 && (method_i as usize) < meta.methods.len() {
                    let m = &meta.methods[method_i as usize];
                    let decl = ts.typedef_full_name(m.declaring_type);
                    let mname = meta.string(m.name_index).unwrap_or_else(|_| "?".into());
                    println!(
                        "    {decl}::{mname} ret={} params={}",
                        ts.name_of_index(m.return_type),
                        m.parameter_count
                    );
                }
                for (label, gi) in [("classInst", class_i), ("methodInst", method_g)] {
                    if gi < 0 {
                        continue;
                    }
                    let Some(inst_ptr) =
                        pe.read_u64_va(located.reg.generic_insts.wrapping_add((gi as u64) * 8))
                    else {
                        println!("    {label}[{gi}] unreadable ptr");
                        continue;
                    };
                    let argc = pe.read_u64_va(inst_ptr).unwrap_or(0);
                    let argv = pe.read_u64_va(inst_ptr + 8).unwrap_or(0);
                    print!("    {label}[{gi}] argc={argc} argv={argv:#x} args=");
                    for i in 0..argc.min(8) {
                        let Some(arg_va) = pe.read_u64_va(argv.wrapping_add(i * 8)) else {
                            print!(" ?");
                            continue;
                        };
                        match ts.read_type_at_va(arg_va) {
                            Ok(t) => match ts.name_of_type(t, 0) {
                                Ok(n) => print!(" {n}"),
                                Err(_) => {
                                    print!(" enum={} klass={}", t.type_enum(), t.klass_index())
                                }
                            },
                            Err(_) => print!(" ty@{arg_va:#x}"),
                        }
                    }
                    println!();
                }
            }
            _ => println!("  unresolved usage={usage} idx={idx}"),
        }
    }
}

#[test]
#[ignore]
fn dump_typeinfo_slots() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    println!("type_ptrs={}", ts.type_ptrs.len());
    for idx in [
        100373i32, 100374, 100375, 141361, 640038, 644267, 640039, 644268,
    ] {
        if idx < 0 || idx as usize >= ts.type_ptrs.len() {
            println!("idx {idx} OOB");
            continue;
        }
        let ty_va = ts.type_ptrs[idx as usize];
        let data = pe.read_u64_va(ty_va).unwrap_or(0);
        let td = data as i32;
        let name = if td >= 0 && (td as usize) < meta.type_defs.len() {
            ts.typedef_full_name(td)
        } else {
            format!("td={td}")
        };
        println!("type_index={idx} ty_va={ty_va:#x} data={data:#x} td={td} {name}");
    }
}

fn dump_method(pe: &PeImage, m: &beyond_schema_dumper::codegen::MethodVa) {
    let n = 320.min(
        pe.data
            .len()
            .saturating_sub(pe.va_to_offset(m.va).unwrap_or(0)),
    );
    if let Some(off) = pe.va_to_offset(m.va) {
        println!(
            "  {} {} va={:#x} {}",
            m.declaring_name,
            m.name,
            m.va,
            hex(&pe.data[off..off + n])
        );
    } else {
        println!("  {} {} va={:#x} UNMAPPED", m.declaring_name, m.name, m.va);
    }
}

/// FKeyframe[] memcpy vs GameplayTag[] formatter, plus InteractiveTemplateVariant / BaseConditionData.
#[test]
#[ignore]
fn dump_v13_remaining() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let mut ts =
        TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");
    let names = [
        "Beyond.FAnimationCurve",
        "Beyond.FKeyframe",
        "Beyond.Gameplay.Core.GameplayTag",
        "Beyond.Gameplay.Core.InteractiveTemplateVariant",
        "Beyond.Gameplay.Core.BaseConditionData",
        "Beyond.Gameplay.InteractiveTemplateData",
        "Beyond.Gameplay.Core.PropertyStateData",
        "Beyond.Gameplay.Core.GameEventsUpdateConfig",
        "Beyond.Gameplay.Core.InteractivePropertyData",
        "Beyond.Gameplay.Core.TargetEntityConfig",
        "Beyond.Gameplay.Actions.SendLuaEvent1",
        "Beyond.Gameplay.Actions.SendLuaEvent",
        "Beyond.Gameplay.Core.CharInteractPerform.SubSpecialPerformEntryData",
        "Beyond.Gameplay.Core.CharInteractPerform.SubSpecialPerformEntry",
        "Beyond.Gameplay.Core.CharInteractPerform.LoopSubSpecialPerformEntry",
        "Beyond.Gameplay.Core.CharInteractPerform.CharInteractPerformRuntimeCfg",
        "Beyond.Gameplay.Core.Entity",
        "UnityEngine.HyperGryph.ECS.Entity",
    ];
    for want in names {
        println!("\n########## {want} ##########");
        for (ti, _) in meta.type_defs.iter().enumerate() {
            let name = ts.typedef_full_name(ti as i32);
            if name != want {
                continue;
            }
            let td = &meta.type_defs[ti];
            println!(
                "  td={ti} flags={:#x} fields={} parent={}",
                td.flags, td.field_count, td.parent_index
            );
            if td.field_count > 0 && td.field_index >= 0 {
                let start = td.field_index as usize;
                for local in 0..td.field_count as usize {
                    let Some(f) = meta.fields.get(start + local) else {
                        break;
                    };
                    let fname = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
                    let ty = ts.name_of_index(f.type_index);
                    println!("    field {fname}: {ty}");
                }
            }
            for m in code.methods.iter().filter(|m| m.typedef_index == ti) {
                if m.name == "Deserialize" || m.name == ".cctor" || m.name == "Serialize" {
                    dump_method_wide(&pe, m, 768);
                    dump_calls(&pe, &code, m, 768);
                    dump_patterns(&pe, m, 768);
                }
            }
        }
        let needle = want.replace(['.', '+', '`'], "_");
        for m in code.methods.iter().filter(|m| {
            m.declaring_name.contains(&needle)
                && m.declaring_name.contains("ForMemoryPack")
                && (m.name == "Deserialize" || m.name == ".cctor")
        }) {
            dump_method_wide(&pe, m, 1024);
            dump_calls(&pe, &code, m, 1024);
            dump_patterns(&pe, m, 1024);
        }
    }
}

fn dump_method_wide(pe: &PeImage, m: &beyond_schema_dumper::codegen::MethodVa, n: usize) {
    let n = n.min(
        pe.data
            .len()
            .saturating_sub(pe.va_to_offset(m.va).unwrap_or(0)),
    );
    if let Some(off) = pe.va_to_offset(m.va) {
        println!(
            "  {} {} va={:#x} {}",
            m.declaring_name,
            m.name,
            m.va,
            hex(&pe.data[off..off + n])
        );
    } else {
        println!("  {} {} va={:#x} UNMAPPED", m.declaring_name, m.name, m.va);
    }
}

fn dump_calls(
    pe: &PeImage,
    code: &beyond_schema_dumper::codegen::CodeMap,
    m: &beyond_schema_dumper::codegen::MethodVa,
    n: usize,
) {
    let Some(bytes) = pe.slice_va(m.va, n) else {
        return;
    };
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().unwrap());
            let target =
                m.va.wrapping_add(i as u64)
                    .wrapping_add(5)
                    .wrapping_add(rel as i64 as u64);
            let name = code
                .methods
                .iter()
                .find(|c| c.va == target)
                .map(|c| format!("{}::{}", c.declaring_name, c.name))
                .unwrap_or_else(|| "unknown".into());
            println!("    call +{i:#x} -> {target:#x} {name}");
            i += 5;
            continue;
        }
        i += 1;
    }
}

fn dump_patterns(pe: &PeImage, m: &beyond_schema_dumper::codegen::MethodVa, n: usize) {
    let Some(bytes) = pe.slice_va(m.va, n) else {
        return;
    };
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        // rex? cmp r/m8, imm8  (80 /7)
        let mut k = i;
        if bytes[k] & 0xF0 == 0x40 {
            k += 1;
        }
        if k + 2 < bytes.len() && bytes[k] == 0x80 && (bytes[k + 1] >> 3) & 7 == 7 {
            let imm_at = k + 2;
            if imm_at < bytes.len() {
                println!(
                    "    cmp-r8-imm +{i:#x} imm={} ({:#x})",
                    bytes[imm_at], bytes[imm_at]
                );
            }
        }
        // imul r, r/m, imm8  (6B)
        if bytes[i] == 0x6B && i + 2 < bytes.len() {
            println!("    imul-imm8 +{i:#x} imm={}", bytes[i + 2] as i8);
        }
        // shl r32, imm8  (C1 /4)
        if bytes[i] == 0xC1 && i + 2 < bytes.len() && (bytes[i + 1] >> 3) & 7 == 4 {
            println!("    shl-imm +{i:#x} imm={}", bytes[i + 2]);
        }
        // rep movsb
        if bytes[i] == 0xF3 && bytes[i + 1] == 0xA4 {
            println!("    rep-movsb +{i:#x}");
        }
        i += 1;
    }
}

/// FKeyframe[] reader + InteractiveTemplateVariant / BaseCondition helpers.
#[test]
#[ignore]
fn dump_v13_helpers() {
    let pe = PeImage::from_path(GA).expect("pe");
    let vas = [
        ("FAnimationCurve.keys-array", 0x1861a1d30u64),
        ("FAnimationCurve.cctor", 0x185e46bf0),
        ("InteractiveTemplateData.bornTag?", 0x1860ecb10),
        ("InteractiveTemplateVariant.cctor", 0x18594ab80),
        ("InteractiveTemplateVariant.Deserialize", 0x186b55230),
        ("BaseCondition nested 1850038c0", 0x1850038c0),
        ("PropertyState string? 1851f2dc0", 0x1851f2dc0),
        ("GameplayTag.Deserialize.cctor", 0x1865a7a90),
        ("ReadObjectHeader-old", 0x184fdfd70),
        ("ReadUInt32-old", 0x184fdf650),
        ("ReadFloat? 184fdfbb0", 0x184fdfbb0),
        ("ReadBool? 184fdfdd0", 0x184fdfdd0),
        ("SendLuaEvent1.Formatter.Deserialize", 0x18c440cb4),
        ("SendLuaEvent2.Formatter.Deserialize", 0x18c4410c4),
        ("header-helper 184fdfd70", 0x184fdfd70),
        ("int-helper 184fdf650", 0x184fdf650),
        ("string-thunk 188aaddc8", 0x188aaddc8),
        ("string-body? 184fdfc10", 0x184fdfc10),
        ("value-helper 185003f90", 0x185003f90),
        ("ReadByte 18997beec", 0x18997beec),
        ("mapped TryReadObjectHeader", 0x18c8c5028),
        ("mapped ReadInt32", 0x189b7f06c),
        ("mapped ReadString", 0x18c8c3b38),
        ("mapped ReadValue a", 0x18a4edf50),
        ("mapped ReadValue b", 0x18c8c3d00),
        ("mapped GetFormatter reader", 0x18c8c3468),
        ("mapped GetFormatter provider a", 0x18c8c253c),
    ];
    for (name, va) in vas {
        let mapped = pe.va_mapped(va);
        println!("\n===== {name} {va:#x} mapped={mapped} =====");
        if let Some(bytes) = pe.slice_va(va, 384) {
            println!("{}", hex(bytes));
            let mut i = 0usize;
            while i + 5 <= bytes.len() {
                if bytes[i] == 0xE8 {
                    let rel = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().unwrap());
                    let target = va
                        .wrapping_add(i as u64)
                        .wrapping_add(5)
                        .wrapping_add(rel as i64 as u64);
                    println!("  call +{i:#x} -> {target:#x}");
                    i += 5;
                    continue;
                }
                i += 1;
            }
            i = 0;
            while i + 3 < bytes.len() {
                if bytes[i] == 0x40 && bytes[i + 1] == 0x80 && bytes[i + 2] == 0xfe {
                    println!("  cmp sil, {:#x} +{i:#x}", bytes[i + 3]);
                }
                if bytes[i] == 0xC1 && i + 2 < bytes.len() && (bytes[i + 1] >> 3) & 7 == 4 {
                    println!("  shl imm={} +{i:#x}", bytes[i + 2]);
                }
                if bytes[i] == 0x6B && i + 2 < bytes.len() {
                    println!("  imul imm8={} +{i:#x}", bytes[i + 2] as i8);
                }
                if bytes[i] == 0x69 && i + 6 < bytes.len() {
                    let imm = i32::from_le_bytes(bytes[i + 2..i + 6].try_into().unwrap_or([0; 4]));
                    if (1..=256).contains(&imm) {
                        println!("  imul imm32={imm} +{i:#x}");
                    }
                }
                if bytes[i] == 0xF3 && bytes[i + 1] == 0xA4 {
                    println!("  rep movsb +{i:#x}");
                }
                if bytes[i] == 0xF3 && bytes[i + 1] == 0xA5 {
                    println!("  rep movsd +{i:#x}");
                }
                i += 1;
            }
        } else {
            println!("UNMAPPED");
        }
    }
}

/// ExtraData `.cctor` `sub eax,1; jne cold` — dump the far target.
#[test]
#[ignore]
fn dump_extra_data_cold() {
    let pe = PeImage::from_path(GA).expect("pe");
    let begin = 0x186c_00390u64;
    let bytes = pe.slice_va(begin, 512).expect("extra .cctor");
    println!(
        "extra.cctor {begin:#x} {}",
        hex(&bytes[..bytes.len().min(192)])
    );
    let mut i = 0usize;
    while i + 6 < bytes.len() {
        if bytes[i] == 0x0F && bytes[i + 1] == 0x85 {
            let rel = i32::from_le_bytes(bytes[i + 2..i + 6].try_into().unwrap());
            let target = begin + i as u64 + 6 + rel as i64 as u64;
            println!("jnz at {begin:#x}+{i:#x} rel={rel:#x} -> {target:#x}");
            if let Some(cold) = pe.slice_va(target, 192) {
                println!("cold {}", hex(cold));
            } else {
                println!("cold UNMAPPED");
            }
        }
        i += 1;
    }
}

/// Prove Optional<T> wire: memcpy vs object header (memberCount 2).
#[test]
#[ignore]
fn dump_optional_native() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let n = located.reg.type_definitions_sizes_count as usize;
    let ptrs = pe
        .read_u64_array_va(located.reg.type_definitions_sizes, n)
        .expect("size ptrs");
    let code = load_code_map(&pe, &meta).expect("code");
    let needles = [
        "Beyond_Optional_float_ForMemoryPack",
        "Beyond_Optional_bool_ForMemoryPack",
        "Beyond_Optional_UnityEngine_Vector3_ForMemoryPack",
        "Beyond_Optional_string_ForMemoryPack",
        "Beyond_Optional_Beyond_Gameplay_Core_AoiRadiusEnum_ForMemoryPack",
        "Beyond_Optional_Beyond_Gameplay_Core_FactionIndex_ForMemoryPack",
        "Beyond_Optional_Beyond_Gameplay_Core_GameplayTag__ForMemoryPack",
        "Beyond_Gameplay_Core_InteractiveTemplateVariantForMemoryPack",
        "Beyond_Gameplay_ParamKeyValueForMemoryPack",
    ];
    println!("--- Optional-related typedef sizes ---");
    for (ti, _) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        if !name.contains("Optional") {
            continue;
        }
        let p = ptrs.get(ti).copied().unwrap_or(0);
        let inst = pe.read_i32_va(p).unwrap_or(-1);
        let native = pe.read_i32_va(p + 4).unwrap_or(-1);
        if inst > 0 || native > 0 {
            println!("  {name} td={ti} instance={inst} native={native}");
        }
    }
    for needle in needles {
        println!("\n########## {needle} ##########");
        let mut n = 0usize;
        for m in code.methods.iter().filter(|m| {
            m.declaring_name.contains(needle)
                && (m.name == "Deserialize" || m.name == ".cctor" || m.name == "Serialize")
        }) {
            n += 1;
            dump_method_wide(&pe, m, 384);
            dump_calls(&pe, &code, m, 384);
            dump_patterns(&pe, m, 384);
        }
        println!("  methods={n}");
    }
}

#[test]
#[ignore]
fn dump_spawner_enemy_library_optional() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let _ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");
    let needle = "SpawnerEnemyLibraryItemForMemoryPack";
    for m in code.methods.iter().filter(|m| {
        m.declaring_name.contains(needle) && (m.name == "Deserialize" || m.name == ".cctor")
    }) {
        dump_method_wide(&pe, m, 2048);
        dump_calls(&pe, &code, m, 2048);
        dump_patterns(&pe, m, 2048);
        if let Some(bytes) = pe.slice_va(m.va, 2048) {
            let mut i = 0usize;
            while i + 4 < bytes.len() {
                let mut k = i;
                if bytes[k] == 0x48 {
                    k += 1;
                }
                if k + 3 < bytes.len() && bytes[k] == 0x83 {
                    let modrm = bytes[k + 1];
                    if (modrm >> 3) & 7 == 0 && modrm >> 6 == 1 && bytes[k + 2] == 0x50 {
                        println!("    add-reader +{i:#x} imm={}", bytes[k + 3] as i8);
                    }
                }
                i += 1;
            }
        }
    }
}

#[test]
#[ignore]
fn dump_spawner_cold_dispatch() {
    let pe = PeImage::from_path(GA).expect("pe");
    // SpawnerActionData ForMemoryPack.cctor: cmp esi,5; jne here
    for (name, va) in [
        ("spawner-tag5-fallthrough", 0x186b0560eu64),
        ("spawner-jne-cold", 0x1877_710e0),
        ("read-unmanaged-helper", 0x184f_dfe50),
    ] {
        println!("\n===== {name} {va:#x} mapped={} =====", pe.va_mapped(va));
        if let Some(bytes) = pe.slice_va(va, 384) {
            println!("{}", hex(bytes));
        }
    }
}

#[test]
#[ignore]
fn dump_send_lua_event() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");
    let names = [
        "Beyond.Gameplay.Actions.SendLuaEvent1",
        "Beyond.Gameplay.Actions.SendLuaEvent2",
        "Beyond.Gameplay.Actions.SendLuaEvent",
        "Beyond.Gameplay.Actions.Param`1<string>",
        "Beyond.Gameplay.Actions.Param`1<object>",
    ];
    for want in names {
        println!("\n########## {want} ##########");
        for (ti, _) in meta.type_defs.iter().enumerate() {
            let name = ts.typedef_full_name(ti as i32);
            if name != want {
                continue;
            }
            let td = &meta.type_defs[ti];
            println!(
                "  td={ti} flags={:#x} fields={} props={} parent={}",
                td.flags, td.field_count, td.property_count, td.parent_index
            );
            if td.property_count > 0 && td.property_index >= 0 {
                let start = td.property_index as usize;
                for local in 0..td.property_count as usize {
                    let Some(p) = meta.properties.get(start + local) else {
                        break;
                    };
                    let pname = meta.string(p.name_index).unwrap_or_else(|_| "?".into());
                    println!("    prop {pname} get={} set={}", p.get, p.set);
                }
            }
            for m in code.methods.iter().filter(|m| m.typedef_index == ti) {
                if m.name == "Deserialize" || m.name == ".cctor" {
                    dump_method_wide(&pe, m, 1024);
                    dump_calls(&pe, &code, m, 1024);
                    dump_patterns(&pe, m, 1024);
                }
            }
        }
        let needle = want.replace(['.', '+', '`', '<', '>'], "_");
        for m in code.methods.iter().filter(|m| {
            m.declaring_name.contains("SendLuaEvent")
                && m.declaring_name.contains("ForMemoryPack")
                && (m.name == "Deserialize" || m.name == ".cctor")
        }) {
            if want.contains("SendLuaEvent") {
                dump_method_wide(&pe, m, 1536);
                dump_calls(&pe, &code, m, 1536);
                dump_patterns(&pe, m, 1536);
            }
        }
        let _ = needle;
    }
}

#[test]
#[ignore]
fn dump_spawner_action() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let _ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");
    let needles = ["SpawnerActionDataForMemoryPack", "SpawnerPreprocess"];
    for needle in needles {
        println!("\n########## {needle} ##########");
        for m in code.methods.iter().filter(|m| {
            m.declaring_name.contains(needle) && (m.name == "Deserialize" || m.name == ".cctor")
        }) {
            dump_method_wide(&pe, m, 1024);
            dump_calls(&pe, &code, m, 1024);
            dump_patterns(&pe, m, 1024);
        }
    }
}

#[test]
#[ignore]
fn dump_remaining_levelscript() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let _located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let code = load_code_map(&pe, &meta).expect("code");
    let needles = [
        "RunePuzzleDataForMemoryPack",
        "SendLuaEvent1ForMemoryPack",
        "SendLuaEvent2ForMemoryPack",
    ];
    for needle in needles {
        println!("\n########## {needle} ##########");
        let mut n = 0usize;
        for m in code.methods.iter().filter(|m| {
            m.declaring_name.contains(needle) && (m.name == "Deserialize" || m.name == ".cctor")
        }) {
            n += 1;
            dump_method_wide(&pe, m, 1536);
            dump_calls(&pe, &code, m, 1536);
            dump_patterns(&pe, m, 1536);
        }
        println!("  methods={n}");
    }
}

/// SendLuaEvent1 nested ReadValue layout: header 07 + mixed UTF-8 / Param.
#[test]
#[ignore]
fn dump_send_lua_manual_value() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let mut ts =
        TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");

    println!("\n===== inheritance fields =====");
    for want in [
        "Beyond.Gameplay.Actions.SendLuaEvent1",
        "Beyond.Gameplay.Actions.ActionBase",
        "Beyond.Gameplay.Actions.Node",
        "Beyond.Gameplay.Actions.NodeBase",
        "Beyond.Gameplay.Actions.Action",
    ] {
        let mut hit = false;
        for (ti, td) in meta.type_defs.iter().enumerate() {
            let name = ts.typedef_full_name(ti as i32);
            if name != want {
                continue;
            }
            hit = true;
            println!(
                "\n{name} td={ti} parent={} fields={} props={}",
                td.parent_index, td.field_count, td.property_count
            );
            let mut cur = ti as i32;
            for depth in 0..8 {
                let cname = ts.typedef_full_name(cur);
                let ctd = &meta.type_defs[cur as usize];
                println!("  [{depth}] {cname} td={cur} fields={}", ctd.field_count);
                if ctd.field_count > 0 && ctd.field_index >= 0 {
                    let start = ctd.field_index as usize;
                    for local in 0..ctd.field_count as usize {
                        let Some(f) = meta.fields.get(start + local) else {
                            break;
                        };
                        let fname = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
                        let fty = ts.name_of_index(f.type_index);
                        let attrs = ts.attrs_of_index(f.type_index);
                        let st = if attrs & beyond_schema_dumper::typesys::field_attrs::STATIC != 0
                        {
                            " static"
                        } else {
                            ""
                        };
                        let vis = if (attrs
                            & beyond_schema_dumper::typesys::field_attrs::FIELD_ACCESS_MASK)
                            == beyond_schema_dumper::typesys::field_attrs::PUBLIC
                        {
                            " public"
                        } else {
                            ""
                        };
                        println!("      {fname}: {fty}{st}{vis}");
                    }
                }
                if ctd.property_count > 0 && ctd.property_index >= 0 {
                    let start = ctd.property_index as usize;
                    for local in 0..ctd.property_count as usize {
                        let Some(p) = meta.properties.get(start + local) else {
                            break;
                        };
                        let pname = meta.string(p.name_index).unwrap_or_else(|_| "?".into());
                        println!("      prop {pname}");
                    }
                }
                match ts.next_parent_typedef(cur) {
                    Some(p) if p != cur => cur = p,
                    _ => break,
                }
            }
        }
        if !hit {
            println!("MISSING {want}");
        }
    }

    println!("\n===== types with Param fields (4..=8 instance fields) =====");
    let mut n = 0usize;
    for (ti, td) in meta.type_defs.iter().enumerate() {
        if td.field_count == 0 || td.field_index < 0 {
            continue;
        }
        let start = td.field_index as usize;
        let mut fields = Vec::new();
        for local in 0..td.field_count as usize {
            let Some(f) = meta.fields.get(start + local) else {
                break;
            };
            let attrs = ts.attrs_of_index(f.type_index);
            if attrs & beyond_schema_dumper::typesys::field_attrs::STATIC != 0
                || attrs & beyond_schema_dumper::typesys::field_attrs::LITERAL != 0
            {
                continue;
            }
            let fname = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
            let fty = ts.name_of_index(f.type_index);
            fields.push((fname, fty));
        }
        let has_param = fields.iter().any(|(_, t)| t.contains("Param`1"));
        if !has_param {
            continue;
        }
        let nfields = fields.len();
        if !(4..=8).contains(&nfields) {
            continue;
        }
        let name = ts.typedef_full_name(ti as i32);
        if name.contains("ForMemoryPack") {
            continue;
        }
        n += 1;
        if n <= 80 {
            println!("  {name} td={ti} n={nfields}");
            for (fnm, fty) in &fields {
                println!("      {fnm}: {fty}");
            }
        }
    }
    println!("param-field types shown {n}");

    println!("\n===== ReadValue methodInst 15583 =====");
    let gi = 15583i32;
    let inst_ptr = pe
        .read_u64_va(located.reg.generic_insts.wrapping_add((gi as u64) * 8))
        .unwrap_or(0);
    let argc = pe.read_u64_va(inst_ptr).unwrap_or(0);
    let argv = pe.read_u64_va(inst_ptr + 8).unwrap_or(0);
    print!("argc={argc} args=");
    for i in 0..argc.min(8) {
        let Some(arg_va) = pe.read_u64_va(argv.wrapping_add(i * 8)) else {
            print!(" ?");
            continue;
        };
        match ts.read_type_at_va(arg_va) {
            Ok(t) => match ts.name_of_type(t, 0) {
                Ok(n) => print!(" {n}"),
                Err(_) => print!(" enum={} klass={}", t.type_enum(), t.klass_index()),
            },
            Err(_) => print!(" ty@{arg_va:#x}"),
        }
    }
    println!();

    println!("\n===== name hits Manual/LuaEvent/eventParam/BBParam =====");
    for (ti, _) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        let lname = name.to_ascii_lowercase();
        if lname.contains("manualvalue")
            || lname.contains("luaevent")
            || lname.contains("eventparam")
            || lname.contains("bbparam")
            || lname.contains("graphparam")
            || name.contains("SerializedValue")
            || name.contains("MemoryPackValue")
        {
            let td = &meta.type_defs[ti];
            println!(
                "  {name} td={ti} fields={} props={}",
                td.field_count, td.property_count
            );
        }
    }

    println!("\n===== SendLuaEvent1 interfaces / methods =====");
    for (ti, td) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        if name != "Beyond.Gameplay.Actions.SendLuaEvent1"
            && name != "Beyond.Gameplay.Actions.SendLuaEvent1+SendLuaEvent1Formatter"
            && name != "Beyond.MemoryPack.Beyond_Gameplay_Actions_SendLuaEvent1ForMemoryPack"
        {
            continue;
        }
        println!(
            "{name} td={ti} ifaces={} methods={} nested={}",
            td.interfaces_count, td.method_count, td.nested_type_count
        );
        if td.method_count > 0 && td.method_index >= 0 {
            for local in 0..td.method_count as usize {
                let mi = td.method_index as usize + local;
                let Some(m) = meta.methods.get(mi) else { break };
                let mname = meta.string(m.name_index).unwrap_or_else(|_| "?".into());
                println!(
                    "  method {mname} ret={} params={}",
                    ts.name_of_index(m.return_type),
                    m.parameter_count
                );
            }
        }
        if td.nested_type_count > 0 {
            for ntd in ts.meta.nested_children(td) {
                println!("  nested {}", ts.typedef_full_name(ntd as i32));
            }
        }
    }

    println!("\n===== MemoryPackReader method names =====");
    for (ti, td) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        if !name.ends_with("MemoryPackReader") && !name.ends_with("MemoryPackWriter") {
            continue;
        }
        println!("{name} methods={}", td.method_count);
        if td.method_count == 0 || td.method_index < 0 {
            continue;
        }
        for local in 0..td.method_count as usize {
            let mi = td.method_index as usize + local;
            let Some(m) = meta.methods.get(mi) else { break };
            let mname = meta.string(m.name_index).unwrap_or_else(|_| "?".into());
            if mname.contains("Header")
                || mname.contains("String")
                || mname.contains("Value")
                || mname.contains("Int")
                || mname.contains("Byte")
                || mname.contains("Bool")
            {
                println!("  {mname} params={}", m.parameter_count);
            }
        }
    }

    println!("\n===== BBParameter fields =====");
    for (ti, td) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        if name != "NodeCanvas.Framework.BBParameter"
            && name != "NodeCanvas.Framework.BBParameter`1"
        {
            continue;
        }
        println!(
            "{name} td={ti} fields={} props={}",
            td.field_count, td.property_count
        );
        if td.field_count > 0 && td.field_index >= 0 {
            let start = td.field_index as usize;
            for local in 0..td.field_count as usize {
                let Some(f) = meta.fields.get(start + local) else {
                    break;
                };
                let fname = meta.string(f.name_index).unwrap_or_else(|_| "?".into());
                let fty = ts.name_of_index(f.type_index);
                println!("  field {fname}: {fty}");
            }
        }
        if td.property_count > 0 && td.property_index >= 0 {
            let start = td.property_index as usize;
            for local in 0..td.property_count as usize {
                let Some(p) = meta.properties.get(start + local) else {
                    break;
                };
                let pname = meta.string(p.name_index).unwrap_or_else(|_| "?".into());
                println!("  prop {pname}");
            }
        }
    }

    println!("\n===== method specs 535858 / 535874 / 625402 =====");
    for idx in [535858i32, 535874, 625402] {
        let spec_va = located.reg.method_specs.wrapping_add((idx as u64) * 12);
        let method_i = pe.read_i32_va(spec_va).unwrap_or(-1);
        let class_i = pe.read_i32_va(spec_va + 4).unwrap_or(-1);
        let method_g = pe.read_i32_va(spec_va + 8).unwrap_or(-1);
        if method_i >= 0 && (method_i as usize) < meta.methods.len() {
            let m = &meta.methods[method_i as usize];
            let decl = ts.typedef_full_name(m.declaring_type);
            let mname = meta.string(m.name_index).unwrap_or_else(|_| "?".into());
            println!("idx {idx} {decl}::{mname} classInst={class_i} methodInst={method_g}");
        }
        if method_g >= 0 {
            let inst_ptr = pe
                .read_u64_va(
                    located
                        .reg
                        .generic_insts
                        .wrapping_add((method_g as u64) * 8),
                )
                .unwrap_or(0);
            let argc = pe.read_u64_va(inst_ptr).unwrap_or(0);
            let argv = pe.read_u64_va(inst_ptr + 8).unwrap_or(0);
            print!("  args=");
            for i in 0..argc.min(8) {
                let Some(arg_va) = pe.read_u64_va(argv.wrapping_add(i * 8)) else {
                    print!(" ?");
                    continue;
                };
                match ts.read_type_at_va(arg_va) {
                    Ok(t) => match ts.name_of_type(t, 0) {
                        Ok(n) => print!(" {n}"),
                        Err(_) => print!(" ?"),
                    },
                    Err(_) => print!(" ?"),
                }
            }
            println!();
        }
    }
}

#[allow(dead_code)]
fn dump_rip_typeinfo(
    pe: &PeImage,
    ts: &TypeSystem<'_>,
    reg: &beyond_schema_dumper::reg::MetadataRegistration,
    va: u64,
    n: usize,
) {
    let Some(bytes) = pe.slice_va(va, n) else {
        return;
    };
    let mut i = 0usize;
    while i + 7 <= bytes.len() {
        if bytes[i] == 0x48 && bytes[i + 1] == 0x8B && matches!(bytes[i + 2], 0x05 | 0x0D | 0x15) {
            let disp = i32::from_le_bytes(bytes[i + 3..i + 7].try_into().unwrap());
            let slot = va
                .wrapping_add(i as u64)
                .wrapping_add(7)
                .wrapping_add(disp as i64 as u64);
            if let Some(enc) = pe.read_u64_va(slot) {
                if enc & 1 == 1 {
                    let usage = ((enc >> 29) & 7) as u32;
                    let idx = ((enc >> 1) & 0x0FFF_FFFF) as i32;
                    println!(
                        "    rip-slot +{i:#x} slot={slot:#x} enc={enc:#x} usage={usage} idx={idx}"
                    );
                    if usage == 1 && idx >= 0 && (idx as usize) < ts.type_ptrs.len() {
                        let ty_va = ts.type_ptrs[idx as usize];
                        let data = pe.read_u64_va(ty_va).unwrap_or(0);
                        let td = data as i32;
                        if td >= 0 && (td as usize) < ts.meta.type_defs.len() {
                            println!("      TypeInfo {}", ts.typedef_full_name(td));
                        }
                    } else if usage == 6 && idx >= 0 && (idx as u64) < reg.method_specs_count {
                        let spec_va = reg.method_specs.wrapping_add((idx as u64) * 12);
                        let method_i = pe.read_i32_va(spec_va).unwrap_or(-1);
                        let method_g = pe.read_i32_va(spec_va + 8).unwrap_or(-1);
                        if method_i >= 0 && (method_i as usize) < ts.meta.methods.len() {
                            let m = &ts.meta.methods[method_i as usize];
                            let decl = ts.typedef_full_name(m.declaring_type);
                            let mname = ts.meta.string(m.name_index).unwrap_or_else(|_| "?".into());
                            println!("      MethodSpec {decl}::{mname} methodInst={method_g}");
                        }
                    }
                }
            }
            i += 7;
            continue;
        }
        i += 1;
    }
}

#[test]
#[ignore]
fn dump_nested_tformatter_wires() {
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");

    println!("\n===== nested T+TFormatter types =====");
    let mut n_fmt = 0usize;
    for (ti, _) in meta.type_defs.iter().enumerate() {
        let name = ts.typedef_full_name(ti as i32);
        if let Some((parent, leaf)) = name.rsplit_once('+') {
            if leaf.ends_with("Formatter") && !leaf.contains("ForMemoryPack") {
                n_fmt += 1;
                if parent.contains("SendLuaEvent") || n_fmt <= 8 {
                    let td = &meta.type_defs[ti];
                    let short = meta.type_name(td).unwrap_or_else(|_| "?".into());
                    println!(
                        "  full={name} short={short} td={ti} methods={}",
                        td.method_count
                    );
                    if td.method_count > 0 && td.method_index >= 0 {
                        for local in 0..td.method_count as usize {
                            let mi = td.method_index as usize + local;
                            let Some(m) = meta.methods.get(mi) else { break };
                            let mname = meta.string(m.name_index).unwrap_or_else(|_| "?".into());
                            println!("    meta {mname} params={}", m.parameter_count);
                        }
                    }
                }
            }
        }
    }
    println!("nested formatters={n_fmt}");

    println!("\n===== code methods SendLuaEvent1Formatter =====");
    let mut n_code = 0usize;
    for m in &code.methods {
        if m.declaring_name.contains("SendLuaEvent1Formatter")
            || m.declaring_name
                .contains("SendLuaEvent1+SendLuaEvent1Formatter")
            || m.declaring_name.ends_with("SendLuaEvent1Formatter")
        {
            n_code += 1;
            println!(
                "  declaring={} name={} va={:#x} td={}",
                m.declaring_name, m.name, m.va, m.typedef_index
            );
            if m.name == "Deserialize" || m.name == "Register" || m.name == ".cctor" {
                // dump_calls is O(n²); skip unless debugging a single method.
            }
        }
    }
    println!("code methods={n_code}");

    println!("\n===== MemoryPackReader / Provider names in code map =====");
    let mut seen = std::collections::BTreeMap::<String, usize>::new();
    for m in &code.methods {
        if m.declaring_name.ends_with("MemoryPackReader")
            || m.declaring_name.ends_with("MemoryPackFormatterProvider")
        {
            *seen
                .entry(format!("{}::{}", m.declaring_name, m.name))
                .or_default() += 1;
        }
    }
    for (k, n) in &seen {
        if k.contains("Header")
            || k.contains("String")
            || k.contains("Int")
            || k.contains("Byte")
            || k.contains("Bool")
            || k.contains("Value")
            || k.contains("GetFormatter")
        {
            println!("  {k} x{n}");
        }
    }
    println!("reader methods total {}", seen.len());

    println!("\n===== TrackingRoute / TrackingBounds ForMemoryPack =====");
    for m in &code.methods {
        if (m.declaring_name.contains("TrackingRouteInfo")
            || m.declaring_name.contains("TrackingBounds"))
            && m.declaring_name.contains("ForMemoryPack")
            && (m.name == "Deserialize" || m.name == ".cctor")
        {
            println!(
                "  declaring={} name={} va={:#x}",
                m.declaring_name, m.name, m.va
            );
            dump_calls(&pe, &code, m, 768);
        }
    }

    println!("\n===== MemoryPackReader method VAs =====");
    for m in &code.methods {
        if !m.declaring_name.ends_with("MemoryPackReader")
            && !m.declaring_name.ends_with("MemoryPackFormatterProvider")
        {
            continue;
        }
        if !(m.name.contains("Header")
            || m.name.contains("String")
            || m.name.contains("Int")
            || m.name.contains("Byte")
            || m.name.contains("Bool")
            || m.name.contains("Value")
            || m.name.contains("GetFormatter")
            || m.name.contains("Unmanaged"))
        {
            continue;
        }
        let b0 = pe.read_u8_va(m.va).unwrap_or(0);
        let follow = if b0 == 0xE9 || b0 == 0xE8 {
            let rel = pe.read_i32_va(m.va + 1).unwrap_or(0);
            m.va.wrapping_add(5).wrapping_add(rel as i64 as u64)
        } else {
            0
        };
        println!(
            "  {:#x} {}::{} b0={:#x} follow={:#x}",
            m.va, m.declaring_name, m.name, b0, follow
        );
    }
}

/// Enemy AnimationConfig leftover: hurtShake dict of unmanaged 8-byte configs.
#[test]
#[ignore]
fn dump_enemy_hurt_shake() {
    use std::collections::HashMap;
    let meta = Metadata::from_path(META).expect("metadata");
    let pe = PeImage::from_path(GA).expect("pe");
    let located = locate_metadata_registration(
        &pe,
        meta.type_defs.len() as u64,
        &LocateOptions {
            force_scan: false,
            known_rva: None,
        },
    )
    .expect("reg");
    let ts = TypeSystem::load(&pe, &meta, located.reg.types, located.reg.types_count).expect("ts");
    let code = load_code_map(&pe, &meta).expect("code");
    let by_va: HashMap<u64, &beyond_schema_dumper::codegen::MethodVa> =
        code.methods.iter().map(|m| (m.va, m)).collect();
    let names = [
        "Beyond.Gameplay.View.Animation.EnemyAnimExtraData",
        "Beyond.Gameplay.View.Animation.EnemyAnimExtraData+EnemyHurtAnimData",
        "Beyond.Gameplay.View.Animation.EnemyAnimExtraData+EnemyHurtShakeIntensityConfig",
        "Beyond.Gameplay.View.Animation.EnemyAnimExtraData+EnemyHurtAnimEntry",
        "Beyond.Gameplay.View.Animation.EnemyHurtConversionConfig",
        "Beyond.Gameplay.View.Animation.EnemyAnimExtraData+EnemyBlowOffAnimConfig",
        "Beyond.Gameplay.View.Animation.EnemyAnimExtraData+EnemyTurnStartData",
        "Beyond.Gameplay.View.Animation.AnimationConfigJson",
    ];
    for want in names {
        println!("\n########## {want} ##########");
        for (ti, _) in meta.type_defs.iter().enumerate() {
            let name = ts.typedef_full_name(ti as i32);
            if name != want && !name.ends_with(want.rsplit(['.', '+']).next().unwrap_or(want)) {
                continue;
            }
            if name != want && !name.contains("ForMemoryPack") && !name.contains("Formatter") {
                continue;
            }
            let td = &meta.type_defs[ti];
            println!(
                "  td={ti} name={name} flags={:#x} fields={} methods={}",
                td.flags, td.field_count, td.method_count
            );
            for m in code.methods.iter().filter(|m| m.typedef_index == ti) {
                if m.name == "Deserialize" || m.name == ".cctor" {
                    dump_method_wide(&pe, m, 1536);
                    dump_patterns(&pe, m, 1536);
                    dump_calls_indexed(&pe, &by_va, m, 1536);
                }
            }
        }
        let leaf = want.rsplit(['.', '+']).next().unwrap_or(want);
        for m in code.methods.iter().filter(|m| {
            m.declaring_name.contains(leaf)
                && m.declaring_name.contains("ForMemoryPack")
                && (m.name == "Deserialize" || m.name == ".cctor")
        }) {
            dump_method_wide(&pe, m, 1536);
            dump_patterns(&pe, m, 1536);
            dump_calls_indexed(&pe, &by_va, m, 1536);
        }
    }
}

fn dump_calls_indexed(
    pe: &PeImage,
    by_va: &std::collections::HashMap<u64, &beyond_schema_dumper::codegen::MethodVa>,
    m: &beyond_schema_dumper::codegen::MethodVa,
    n: usize,
) {
    let Some(bytes) = pe.slice_va(m.va, n) else {
        return;
    };
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().unwrap());
            let target =
                m.va.wrapping_add(i as u64)
                    .wrapping_add(5)
                    .wrapping_add(rel as i64 as u64);
            let name = by_va
                .get(&target)
                .map(|c| format!("{}::{}", c.declaring_name, c.name))
                .unwrap_or_else(|| "unknown".into());
            println!("    call +{i:#x} -> {target:#x} {name}");
            i += 5;
            continue;
        }
        i += 1;
    }
}
