// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Context;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use utils::errors::Result;

mod crypto;
mod utils;

fn main() -> Result<()> {
    let file_appender = tracing_appender::rolling::daily("./log", "app.log");

    let (std_writer, _guard) =
        tracing_appender::non_blocking(std::io::stdout());
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
        .compact()
        .with_writer(std_writer.and(file_writer))
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)
        .context("initial tracing subscriber failed")?;

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            // key generator
            crypto::aes::generate_aes,
            crypto::aes::generate_iv,
            crypto::rsa::generate_rsa,
            crypto::rsa::derive_rsa,
            crypto::ecc::generate_ecc,
            crypto::ecc::derive_ecc,
            crypto::ecc::ecies,
            crypto::edwards::generate_edwards,
            crypto::edwards::derive_edwards,
            crypto::edwards::ecies_edwards,
            // encrytion
            crypto::aes::crypto_aes,
            crypto::rsa::crypto_rsa,
            crypto::ecc::ecies,
            // format
            crypto::rsa::transfer_rsa_key,
            crypto::ecc::transfer_ecc_key,
            crypto::edwards::transfer_edwards_key,
            utils::codec::base64_encode,
            utils::codec::base64_decode,
            utils::codec::hex_encode,
            utils::codec::hex_decode,
            utils::codec::string_encode,
            utils::codec::string_decode
        ])
        .run(tauri::generate_context!())
        .context("error while running tauri application")?;
    Ok(())
}
