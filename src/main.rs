use std::{
    cmp::{max, min},
    fs::File,
    io::prelude::*,
    path::PathBuf,
};

struct StateVariables {
    compressed_current: usize,
    compressed_record_end: usize,
    decompressed_current: usize,
    compressed_chunk_start: usize,
    decompressed_chunk_start: usize,
    compressed_end: usize,
}

struct CopyTokenInfo {
    copy_token_offset: u16,
    length: u16,
}

struct CopyTokenHelpInfo {
    length_mask: u16,
    offset_mask: u16,
    bit_count: u16,
    maximum_length: u16,
}

fn main() {
    // let compressed_bytes: [u8; 471] = [
    //     0x01, // SignatureByte
    //     0xD3, 0xB1, // CompressedChunkHeader
    //     0x80, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x30, 0x2A, 0x02, 0x02, 0x90, 0x09,
    //     0x00, 0x70, 0x14, 0x06, 0x48, 0x03, 0x00, 0x82, 0x02, 0x00, 0x64, 0xA8, 0x03, 0x04, 0x00,
    //     0x0A, 0x00, 0x1C, 0x00, 0x56, 0x42, 0x41, 0x50, 0x72, 0x6F, 0x6A, 0x65, 0x88, 0x63, 0x74,
    //     0x05, 0x00, 0x34, 0x00, 0x00, 0x40, 0x02, 0x14, 0x6A, 0x06, 0x02, 0x0A, 0x3D, 0x02, 0x0A,
    //     0x07, 0x02, 0x72, 0x01, 0x14, 0x08, 0x05, 0x06, 0x12, 0x09, 0x02, 0x12, 0xF4, 0x23, 0xBA,
    //     0x66, 0x04, 0x94, 0x00, 0x0C, 0x02, 0x4A, 0x3C, 0x02, 0x0A, 0x16, 0x00, 0x01, 0x72, 0x80,
    //     0x73, 0x74, 0x64, 0x6F, 0x6C, 0x65, 0x3E, 0x02, 0x19, 0x00, 0x73, 0x00, 0x74, 0x00, 0x64,
    //     0x00, 0x6F, 0x00, 0x80, 0x6C, 0x00, 0x65, 0x00, 0x0D, 0x00, 0x68, 0x00, 0x25, 0x02, 0x5E,
    //     0x00, 0x03, 0x2A, 0x5C, 0x47, 0x7B, 0x30, 0x30, 0x80, 0x30, 0x32, 0x30, 0x34, 0x33, 0x30,
    //     0x2D, 0x00, 0x08, 0x1D, 0x04, 0x04, 0x43, 0x00, 0x0A, 0x02, 0x0E, 0x01, 0x12, 0x30, 0x30,
    //     0x34, 0x00, 0x36, 0x7D, 0x23, 0x32, 0x2E, 0x30, 0x23, 0x30, 0x00, 0x23, 0x43, 0x3A, 0x5C,
    //     0x57, 0x69, 0x6E, 0x64, 0x00, 0x6F, 0x77, 0x73, 0x5C, 0x53, 0x79, 0x73, 0x74, 0x20, 0x65,
    //     0x6D, 0x33, 0x32, 0x5C, 0x03, 0x65, 0x32, 0x2E, 0x00, 0x74, 0x6C, 0x62, 0x23, 0x4F, 0x4C,
    //     0x45, 0x20, 0x00, 0x41, 0x75, 0x74, 0x6F, 0x6D, 0x61, 0x74, 0x69, 0x1C, 0x6F, 0x6E, 0x00,
    //     0x60, 0x00, 0x01, 0x83, 0x45, 0x4F, 0x66, 0x66, 0x44, 0x69, 0x63, 0x84, 0x45, 0x4F, 0x00,
    //     0x66, 0x80, 0x00, 0x69, 0xD4, 0x00, 0x63, 0x82, 0x45, 0x9E, 0x80, 0x11, 0x94, 0x80, 0x01,
    //     0x81, 0x45, 0x00, 0x32, 0x44, 0x46, 0x38, 0x44, 0x30, 0x34, 0x43, 0x00, 0x2D, 0x35, 0x42,
    //     0x46, 0x41, 0x2D, 0x31, 0x30, 0x80, 0x31, 0x42, 0x2D, 0x42, 0x44, 0x45, 0x35, 0x80, 0x45,
    //     0xD4, 0x41, 0x41, 0x80, 0x43, 0x34, 0x80, 0x05, 0x32, 0x88, 0x45, 0x80, 0x98, 0x00, 0x67,
    //     0x72, 0x61, 0x6D, 0x20, 0x46, 0x69, 0x6C, 0x00, 0x65, 0x73, 0x5C, 0x43, 0x6F, 0x6D, 0x6D,
    //     0x6F, 0x02, 0x6E, 0x04, 0x06, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x00, 0x6F, 0x66, 0x74,
    //     0x20, 0x53, 0x68, 0x61, 0x72, 0x00, 0x65, 0x64, 0x5C, 0x4F, 0x46, 0x46, 0x49, 0x43, 0x00,
    //     0x45, 0x31, 0x36, 0x5C, 0x4D, 0x53, 0x4F, 0x2E, 0x30, 0x44, 0x4C, 0x4C, 0x23, 0x87, 0x10,
    //     0x83, 0x4D, 0x20, 0x31, 0x40, 0x36, 0x2E, 0x30, 0x20, 0x4F, 0x62, 0x81, 0xC1, 0x20, 0x80,
    //     0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x00, 0x4B, 0x45, 0x00, 0x01, 0x0F, 0x82, 0xD4,
    //     0x02, 0x00, 0x13, 0x83, 0xD8, 0xC5, 0x04, 0x19, 0x00, 0x81, 0xD1, 0xC4, 0xA3, 0xBF, 0xE9,
    //     0x31, 0x02, 0x47, 0x02, 0xB4, 0x21, 0x6A, 0x57, 0x57, 0x31, 0x00, 0xAA, 0x1A, 0x07, 0x0B,
    //     0x32, 0x08, 0x0B, 0x1C, 0x02, 0x11, 0x48, 0x42, 0x01, 0x6A, 0x31, 0xC2, 0x6B, 0xF3, 0xC0,
    //     0x81, 0x1E, 0x42, 0x02, 0x01, 0x05, 0x2C, 0xD1, 0x42, 0x15, 0x97, 0x88, 0x21, 0x42, 0x08,
    //     0x2B, 0x42, 0x01, 0x47, 0x18, 0x2A, 0x32, 0x47, 0x18, 0x32, 0x48, 0x18, 0x32, 0x47, 0x18,
    //     0x32, 0x00, 0x4D, 0x4F, 0x18, 0xE3, 0x80, 0x94, 0x4D, 0x18, 0xE5, 0xFE, 0x49, 0x18, 0x10,
    //     0x01, 0xC2, 0x1,
    // ];
    // let mut file = File::open("compressed.bin").expect("no file found");
    // let metadata = std::fs::metadata("compressed.bin").expect("unable to read metadata");
    // let mut compressed_bytes = vec![0; metadata.len() as usize];
    // file.read(&mut compressed_bytes).expect("buffer overflow");
    // let compressed_bytes = Vec::from([
    //     0x01, 0xD3, 0xB1, 0x80, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x30, 0x2A, 0x02,
    //     0x02, 0x90, 0x09, 0x00, 0x70, 0x14, 0x06, 0x48, 0x03, 0x00, 0x82, 0x02, 0x00, 0x64, 0xA8,
    //     0x03, 0x04, 0x00, 0x0A, 0x00, 0x1C, 0x00, 0x56, 0x42, 0x41, 0x50, 0x72, 0x6F, 0x6A, 0x65,
    //     0x88, 0x63, 0x74, 0x05, 0x00, 0x34, 0x00, 0x00, 0x40, 0x02, 0x14, 0x6A, 0x06, 0x02, 0x0A,
    //     0x3D, 0x02, 0x0A, 0x07, 0x02, 0x72, 0x01, 0x14, 0x08, 0x05, 0x06, 0x12, 0x09, 0x02, 0x12,
    //     0xF4, 0x23, 0xBA, 0x66, 0x04, 0x94, 0x00, 0x0C, 0x02, 0x4A, 0x3C, 0x02, 0x0A, 0x16, 0x00,
    //     0x01, 0x72, 0x80, 0x73, 0x74, 0x64, 0x6F, 0x6C, 0x65, 0x3E, 0x02, 0x19, 0x00, 0x73, 0x00,
    //     0x74, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x80, 0x6C, 0x00, 0x65, 0x00, 0x0D, 0x00, 0x68, 0x00,
    //     0x25, 0x02, 0x5E, 0x00, 0x03, 0x2A, 0x5C, 0x47, 0x7B, 0x30, 0x30, 0x80, 0x30, 0x32, 0x30,
    //     0x34, 0x33, 0x30, 0x2D, 0x00, 0x08, 0x1D, 0x04, 0x04, 0x43, 0x00, 0x0A, 0x02, 0x0E, 0x01,
    //     0x12, 0x30, 0x30, 0x34, 0x00, 0x36, 0x7D, 0x23, 0x32, 0x2E, 0x30, 0x23, 0x30, 0x00, 0x23,
    //     0x43, 0x3A, 0x5C, 0x57, 0x69, 0x6E, 0x64, 0x00, 0x6F, 0x77, 0x73, 0x5C, 0x53, 0x79, 0x73,
    //     0x74, 0x20, 0x65, 0x6D, 0x33, 0x32, 0x5C, 0x03, 0x65, 0x32, 0x2E, 0x00, 0x74, 0x6C, 0x62,
    //     0x23, 0x4F, 0x4C, 0x45, 0x20, 0x00, 0x41, 0x75, 0x74, 0x6F, 0x6D, 0x61, 0x74, 0x69, 0x1C,
    //     0x6F, 0x6E, 0x00, 0x60, 0x00, 0x01, 0x83, 0x45, 0x4F, 0x66, 0x66, 0x44, 0x69, 0x63, 0x84,
    //     0x45, 0x4F, 0x00, 0x66, 0x80, 0x00, 0x69, 0xD4, 0x00, 0x63, 0x82, 0x45, 0x9E, 0x80, 0x11,
    //     0x94, 0x80, 0x01, 0x81, 0x45, 0x00, 0x32, 0x44, 0x46, 0x38, 0x44, 0x30, 0x34, 0x43, 0x00,
    //     0x2D, 0x35, 0x42, 0x46, 0x41, 0x2D, 0x31, 0x30, 0x80, 0x31, 0x42, 0x2D, 0x42, 0x44, 0x45,
    //     0x35, 0x80, 0x45, 0xD4, 0x41, 0x41, 0x80, 0x43, 0x34, 0x80, 0x05, 0x32, 0x88, 0x45, 0x80,
    //     0x98, 0x00, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x46, 0x69, 0x6C, 0x00, 0x65, 0x73, 0x5C, 0x43,
    //     0x6F, 0x6D, 0x6D, 0x6F, 0x02, 0x6E, 0x04, 0x06, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x00,
    //     0x6F, 0x66, 0x74, 0x20, 0x53, 0x68, 0x61, 0x72, 0x00, 0x65, 0x64, 0x5C, 0x4F, 0x46, 0x46,
    //     0x49, 0x43, 0x00, 0x45, 0x31, 0x36, 0x5C, 0x4D, 0x53, 0x4F, 0x2E, 0x30, 0x44, 0x4C, 0x4C,
    //     0x23, 0x87, 0x10, 0x83, 0x4D, 0x20, 0x31, 0x40, 0x36, 0x2E, 0x30, 0x20, 0x4F, 0x62, 0x81,
    //     0xC1, 0x20, 0x80, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x00, 0x4B, 0x45, 0x00, 0x01,
    //     0x0F, 0x82, 0xD4, 0x02, 0x00, 0x13, 0x83, 0xD8, 0xC5, 0x04, 0x19, 0x00, 0x81, 0xD1, 0xC4,
    //     0xA3, 0xBF, 0xE9, 0x31, 0x02, 0x47, 0x02, 0xB4, 0x21, 0x6A, 0x57, 0x57, 0x31, 0x00, 0xAA,
    //     0x1A, 0x07, 0x0B, 0x32, 0x08, 0x0B, 0x1C, 0x02, 0x11, 0x48, 0x42, 0x01, 0x6A, 0x31, 0xC2,
    //     0x6B, 0xF3, 0xC0, 0x81, 0x1E, 0x42, 0x02, 0x01, 0x05, 0x2C, 0xD1, 0x42, 0x15, 0x97, 0x88,
    //     0x21, 0x42, 0x08, 0x2B, 0x42, 0x01, 0x47, 0x18, 0x2A, 0x32, 0x47, 0x18, 0x32, 0x48, 0x18,
    //     0x32, 0x47, 0x18, 0x32, 0x00, 0x4D, 0x4F, 0x18, 0xE3, 0x80, 0x94, 0x4D, 0x18, 0xE5, 0xFE,
    //     0x49, 0x18, 0x10, 0x01, 0xC2, 0x19,
    // ]);
    // My VBA stream below
    let compressed_bytes = Vec::from([
        0x01, 0xCA, 0xB1, 0x80, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x30, 0x56, 0x4A,
        0x02, 0x90, 0x01, 0xD0, 0x02, 0x02, 0x48, 0x09, 0x00, 0x50, 0x14, 0x11, 0x06, 0x48, 0x03,
        0x00, 0x02, 0x00, 0x8C, 0xE4, 0x04, 0x04, 0x04, 0x00, 0x0A, 0x00, 0x1C, 0x56, 0x42, 0x41,
        0x50, 0x72, 0x40, 0x6F, 0x6A, 0x65, 0x63, 0x74, 0x05, 0x00, 0x1A, 0x00, 0x54, 0x00, 0x40,
        0x02, 0x0A, 0x06, 0x02, 0x0A, 0x3D, 0x02, 0x0A, 0x07, 0x2B, 0x02, 0x72, 0x01, 0x14, 0x08,
        0x06, 0x12, 0x09, 0x02, 0x12, 0xFD, 0x9B, 0xA0, 0x03, 0x67, 0x05, 0x00, 0x0C, 0x02, 0x4A,
        0x3C, 0x02, 0x0A, 0x04, 0x16, 0x00, 0x01, 0x39, 0x73, 0x74, 0x64, 0x6F, 0x6C, 0x04, 0x65,
        0x3E, 0x02, 0x19, 0x73, 0x00, 0x74, 0x00, 0x64, 0x00, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x65,
        0x00, 0x0D, 0x14, 0x00, 0x68, 0x00, 0x25, 0x5E, 0x00, 0x03, 0x2A, 0x5C, 0x47, 0x00, 0x7B,
        0x30, 0x30, 0x30, 0x32, 0x30, 0x34, 0x33, 0xEC, 0x30, 0x2D, 0x00, 0x08, 0x04, 0x04, 0x43,
        0x00, 0x0A, 0x02, 0x0E, 0x01, 0x12, 0x00, 0x30, 0x30, 0x34, 0x36, 0x7D, 0x23, 0x32, 0x2E,
        0x00, 0x30, 0x23, 0x30, 0x23, 0x43, 0x3A, 0x5C, 0x57, 0x00, 0x69, 0x6E, 0x64, 0x6F, 0x77,
        0x73, 0x5C, 0x53, 0x00, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x33, 0x32, 0x5C, 0x01, 0x03, 0x65,
        0x32, 0x2E, 0x74, 0x6C, 0x62, 0x23, 0x4F, 0x00, 0x4C, 0x45, 0x20, 0x41, 0x75, 0x74, 0x6F,
        0x6D, 0xE0, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x30, 0x00, 0x01, 0x83, 0x45, 0x20, 0x4F,
        0x66, 0x66, 0x69, 0x63, 0x84, 0x45, 0x4F, 0x00, 0xA2, 0x66, 0x80, 0x00, 0x69, 0x00, 0x63,
        0x82, 0x45, 0x9E, 0x80, 0x11, 0x06, 0x94, 0x80, 0x01, 0x81, 0x45, 0x32, 0x44, 0x46, 0x38,
        0x44, 0x00, 0x30, 0x34, 0x43, 0x2D, 0x35, 0x42, 0x46, 0x41, 0x00, 0x2D, 0x31, 0x30, 0x31,
        0x42, 0x2D, 0x42, 0x44, 0xA4, 0x45, 0x35, 0x80, 0x45, 0x41, 0x41, 0x80, 0x43, 0x34, 0x80,
        0x05, 0x06, 0x32, 0x88, 0x45, 0x80, 0x98, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x00, 0x46, 0x69,
        0x6C, 0x65, 0x73, 0x5C, 0x43, 0x6F, 0x10, 0x6D, 0x6D, 0x6F, 0x6E, 0x04, 0x06, 0x4D, 0x69,
        0x63, 0x00, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x53, 0x00, 0x68, 0x61, 0x72, 0x65,
        0x64, 0x5C, 0x4F, 0x46, 0x00, 0x46, 0x49, 0x43, 0x45, 0x31, 0x36, 0x5C, 0x4D, 0x80, 0x53,
        0x4F, 0x2E, 0x44, 0x4C, 0x4C, 0x23, 0x87, 0x10, 0x01, 0x83, 0x4D, 0x20, 0x31, 0x36, 0x2E,
        0x30, 0x20, 0x4F, 0x02, 0x62, 0x81, 0xC1, 0x20, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x2C, 0x72,
        0x79, 0x00, 0x4B, 0x00, 0x01, 0x0F, 0x82, 0xD4, 0x01, 0x00, 0x82, 0x13, 0x82, 0x03, 0xF1,
        0x03, 0x19, 0x00, 0x07, 0x80, 0x0A, 0x00, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x31, 0x47,
        0x8C, 0x00, 0x0E, 0x01, 0x06, 0x00, 0xAD, 0x64, 0x00, 0x75, 0x02, 0xAF, 0xA8, 0x31, 0x00,
        0x1A, 0x09, 0x08, 0x32, 0x10, 0x08, 0x1C, 0x80, 0x0C, 0xA8, 0x00, 0x00, 0x48, 0x42, 0x01,
        0x31, 0xC2, 0x70, 0xFB, 0x00, 0x8C, 0x16, 0x1E, 0x42, 0x02, 0x01, 0x05, 0x2C, 0x42, 0x1A,
        0xC6, 0x4A, 0x21, 0x15, 0x42, 0x08, 0x2B, 0x42, 0x01, 0x10, 0x42, 0x01,
    ]);

    let mut decompressed_bytes: Vec<u8> = Vec::new();

    // 2.4.1.2 State Variables (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/c01d4c55-f44e-4ee1-b5cd-e179e4957d01)
    let mut state_variables = StateVariables {
        compressed_current: 0,
        compressed_record_end: compressed_bytes.len() - 1,
        compressed_chunk_start: 0,
        decompressed_current: 0,
        decompressed_chunk_start: 0,
        compressed_end: 0,
    };

    println!("Hello, world!");

    decompress(
        &compressed_bytes,
        &mut decompressed_bytes,
        &mut state_variables,
    );
}

// 2.4.1.3.1 Decompression Algorithm (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/492124cc-5afc-48c8-b439-b42ad7087a7b)
fn decompress(
    compressed_bytes: &Vec<u8>,
    decompressed_bytes: &mut Vec<u8>,
    state: &mut StateVariables,
) {
    if compressed_bytes[0] == 1 {
        state.compressed_current += 1;

        while state.compressed_current < state.compressed_record_end {
            state.compressed_chunk_start = state.compressed_current;

            decompress_chunk(compressed_bytes, decompressed_bytes, state);
        }
    } else {
        panic!("Invalid compression");
    }
    let mut file = File::create("complete_decrypted.bytes.txt").unwrap();
    let mut f = File::create("complete_decrypted.txt").unwrap();
    file.write_all(String::from_utf8_lossy(decompressed_bytes).as_bytes())
        .unwrap();
    for byte in decompressed_bytes.iter() {
        write!(f, "{:#04X?} ", byte).unwrap();
    }
}

// 2.4.1.3.2 Decompressing a CompressedChunk (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/3d5ea4df-e8a5-4079-a454-9595b840525f)
fn decompress_chunk(
    compressed_bytes: &Vec<u8>,
    decompressed_bytes: &mut Vec<u8>,
    state: &mut StateVariables,
) {
    let header = u16::from_le_bytes([
        compressed_bytes[state.compressed_current],
        compressed_bytes[state.compressed_current + 1],
    ]);

    let chunk_size = extract_compressed_chunk_size(&header);
    let compressed_chunk_flag = extract_compressed_chunk_flag(&header);
    state.decompressed_chunk_start = state.decompressed_current;
    state.compressed_end = min(
        state.compressed_record_end,
        state.compressed_chunk_start + usize::from(chunk_size),
    );
    state.compressed_current = state.compressed_chunk_start + 2;

    if compressed_chunk_flag == 1 {
        while state.compressed_current < state.compressed_end {
            decompress_token_sequence(compressed_bytes, decompressed_bytes, state);
        }
    } else {
        println!("Uncompressed chunk");
    }
}

// 2.4.1.3.12 Extract CompressedChunkSize (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/4994c768-d35d-497d-937d-d577611cb17f)
fn extract_compressed_chunk_size(header: &u16) -> u16 {
    (header & 0x0FFF) + 3
}

// 2.4.1.3.15 Extract CompressedChunkFlag (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/a954990f-b3d3-43e0-8d52-3d86d1f5b9af)
fn extract_compressed_chunk_flag(header: &u16) -> u16 {
    (header & 0x8000) >> 15
}

// 2.4.1.3.4 Decompressing a TokenSequence (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/70ea7393-cc0d-4efd-ae18-853f29a062c8)
fn decompress_token_sequence(
    compressed_bytes: &Vec<u8>,
    decompressed_bytes: &mut Vec<u8>,
    state: &mut StateVariables,
) {
    let flag_byte = compressed_bytes[state.compressed_current];
    state.compressed_current += 1;

    let mut i = 0;

    while i <= 7 {
        if state.compressed_current < state.compressed_end {
            decompress_token(&compressed_bytes, decompressed_bytes, &i, flag_byte, state);
            i += 1;
        } else {
            break;
        }
    }
}

// 2.4.1.3.5 Decompressing a Token (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/d7069c13-458a-4020-83b3-1f3f49450e9e)
fn decompress_token(
    compressed_bytes: &Vec<u8>,
    decompressed_bytes: &mut Vec<u8>,
    index: &usize,
    flag_byte: u8,
    state: &mut StateVariables,
) {
    let flag_bit = extract_flag_bit(index, flag_byte);

    if flag_bit == 0 {
        if state.compressed_current >= 462 {
            let mut file = File::create("out_of_bounds.3.txt").unwrap();
            let mut f = File::create("out_of_bounds.3.bytes.txt").unwrap();
            f.write_all(String::from_utf8_lossy(&decompressed_bytes).as_bytes())
                .unwrap();
            for byte in decompressed_bytes.iter() {
                write!(file, "{:#04X?} ", byte).unwrap();
            }
        }

        decompressed_bytes.insert(
            state.decompressed_current,
            compressed_bytes[state.compressed_current],
        );
        state.compressed_current += 1;
        state.decompressed_current += 1;
    } else {
        let copy_token = u16::from_le_bytes([
            compressed_bytes[state.compressed_current],
            compressed_bytes[state.compressed_current + 1],
        ]);
        let CopyTokenInfo {
            copy_token_offset,
            length,
        } = unpack_copy_token(copy_token, state);

        // let foo = state.decompressed_current;
        // if foo < copy_token_offset as usize {
        //     // println!("{:#04X?}", decomp);
        //     let mut file = File::create("foo.txt").unwrap();
        //     file.write_all(String::from_utf8_lossy(decomp).as_bytes())
        //         .unwrap();
        // }

        let copy_source: usize = state.decompressed_current - usize::from(copy_token_offset);

        byte_copy(
            copy_source,
            state.decompressed_current,
            length,
            decompressed_bytes,
        );

        state.decompressed_current += usize::from(length);
        state.compressed_current += 2;
    }
}

// 2.4.1.3.17 Extract FlagBit (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/ff4680fd-b2af-4d3f-bb86-7d5d296218f6)
fn extract_flag_bit(index: &usize, flag_byte: u8) -> u8 {
    (flag_byte >> index) & 1
}

// 2.4.1.3.19.2 Unpack CopyToken (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/6a77ef81-79da-41a9-9b7b-a4c807f326d5)
fn unpack_copy_token(copy_token: u16, state: &StateVariables) -> CopyTokenInfo {
    let copy_token_help_info = copy_token_help(state);
    let length: u16 = (copy_token & copy_token_help_info.length_mask) + 3;
    let temp1: u16 = copy_token & copy_token_help_info.offset_mask;
    let temp2: u16 = 16 - copy_token_help_info.bit_count;
    let offset: u16 = (temp1 >> temp2) + 1;

    CopyTokenInfo {
        copy_token_offset: offset,
        length,
    }
}

// 2.4.1.3.19.1 CopyToken Help (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/220bde4c-02b5-41ef-9f9a-8608718ce913)
fn copy_token_help(state: &StateVariables) -> CopyTokenHelpInfo {
    let difference =
        f64::from((state.decompressed_current - state.decompressed_chunk_start) as u32);
    let mut bit_count = difference.log2().ceil() as u16;
    bit_count = max(bit_count, 4);
    let length_mask: u16 = 0xFFFF >> bit_count;
    let offset_mask = !length_mask;
    let maximum_length = (0xFFFF >> bit_count) + 3;

    CopyTokenHelpInfo {
        length_mask,
        offset_mask,
        bit_count,
        maximum_length,
    }
}

// 2.4.1.3.11 Byte Copy (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/7b75cf79-b736-47db-96ab-a443636518a8)
fn byte_copy(copy_source: usize, destination_source: usize, byte_count: u16, decomp: &mut Vec<u8>) {
    let mut src_current = copy_source;
    let mut dst_current = destination_source;
    let mut count = 1;

    while count <= byte_count {
        decomp.insert(dst_current, decomp[src_current]);

        src_current += 1;
        dst_current += 1;

        count += 1;
    }
    // for _count in 1..byte_count {
    //     decomp.insert(dst_current, comp[src_current]);

    //     src_current += 1;
    //     dst_current += 1;
    // }
}