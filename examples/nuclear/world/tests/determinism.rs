#[test]
fn model_sources_use_fixed_arithmetic_without_clocks() {
    let sources = [
        ("kinetics", include_str!("../src/kinetics.rs")),
        ("plant", include_str!("../src/plant.rs")),
        ("commands", include_str!("../src/plant/commands.rs")),
        ("steam", include_str!("../src/steam.rs")),
        ("sensors", include_str!("../src/sensors.rs")),
        ("protection", include_str!("../src/protection.rs")),
        ("faults", include_str!("../src/faults.rs")),
        ("command", include_str!("../src/command.rs")),
        ("snapshot", include_str!("../src/snapshot.rs")),
        ("stages", include_str!("../src/stages.rs")),
        ("severe", include_str!("../src/severe.rs")),
        ("primary", include_str!("../src/severe/primary.rs")),
        ("core", include_str!("../src/severe/core.rs")),
        ("vessel", include_str!("../src/severe/vessel.rs")),
        ("containment", include_str!("../src/severe/containment.rs")),
        ("cavity", include_str!("../src/severe/cavity.rs")),
        ("spaces", include_str!("../src/severe/spaces.rs")),
        ("stylized", include_str!("../src/stylized.rs")),
        ("scenarios", include_str!("../src/scenarios.rs")),
    ];
    let forbidden = [
        ".exp(",
        ".exp2(",
        ".exp_m1(",
        ".ln(",
        ".ln_1p(",
        ".log(",
        ".log2(",
        ".log10(",
        ".powf(",
        ".powi(",
        ".sqrt(",
        ".cbrt(",
        ".sin(",
        ".cos(",
        ".tan(",
        ".sinh(",
        ".cosh(",
        ".tanh(",
        ".asin(",
        ".acos(",
        ".atan(",
        ".atan2(",
        ".hypot(",
        "mul_add",
        "Instant",
        "SystemTime",
    ];
    for (name, source) in sources {
        let model = source.split("#[cfg(test)]").next().unwrap();
        let compact: String = model.chars().filter(|c| !c.is_whitespace()).collect();
        for call in forbidden {
            assert!(!compact.contains(call), "{name} contains {call}");
        }
    }
}
