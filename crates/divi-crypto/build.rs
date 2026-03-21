// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

fn main() {
    let crypto_dir = "csrc";

    cc::Build::new()
        .files([
            format!("{crypto_dir}/blake.c"),
            format!("{crypto_dir}/bmw.c"),
            format!("{crypto_dir}/groestl.c"),
            format!("{crypto_dir}/jh.c"),
            format!("{crypto_dir}/keccak.c"),
            format!("{crypto_dir}/skein.c"),
        ])
        .include(crypto_dir)
        .warnings(false)
        .compile("sph_crypto");

    println!("cargo:rerun-if-changed={crypto_dir}/blake.c");
    println!("cargo:rerun-if-changed={crypto_dir}/bmw.c");
    println!("cargo:rerun-if-changed={crypto_dir}/groestl.c");
    println!("cargo:rerun-if-changed={crypto_dir}/jh.c");
    println!("cargo:rerun-if-changed={crypto_dir}/keccak.c");
    println!("cargo:rerun-if-changed={crypto_dir}/skein.c");
    println!("cargo:rerun-if-changed={crypto_dir}/sph_blake.h");
    println!("cargo:rerun-if-changed={crypto_dir}/sph_bmw.h");
    println!("cargo:rerun-if-changed={crypto_dir}/sph_groestl.h");
    println!("cargo:rerun-if-changed={crypto_dir}/sph_jh.h");
    println!("cargo:rerun-if-changed={crypto_dir}/sph_keccak.h");
    println!("cargo:rerun-if-changed={crypto_dir}/sph_skein.h");
    println!("cargo:rerun-if-changed={crypto_dir}/sph_types.h");
    println!("cargo:rerun-if-changed=build.rs");
}
