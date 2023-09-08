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
    let mut file = File::open("compressed.bin").expect("no file found");
    let metadata = std::fs::metadata("compressed.bin").expect("unable to read metadata");
    let mut compressed_bytes = vec![0; metadata.len() as usize];
    file.read(&mut compressed_bytes).expect("buffer overflow");

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
    let mut file = File::create("complete_decompressed.bin").unwrap();
    let mut file2 = File::create("complete_decompressed.txt").unwrap();

    file.write_all(String::from_utf8_lossy(decompressed_bytes).as_bytes())
        .unwrap();

    for byte in decompressed_bytes.iter() {
        write!(file2, "{:#04X?} ", byte).unwrap();
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
        decompress_raw_chunk(compressed_bytes, decompressed_bytes, state);
    }
}

// 2.4.1.3.3 Decompressing a RawChunk (https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/86ff30e6-9442-4232-ba00-e616c64fd9ac)
fn decompress_raw_chunk(
    compressed_bytes: &Vec<u8>,
    decompressed_bytes: &mut Vec<u8>,
    state: &mut StateVariables,
) {
    let bytes = &compressed_bytes[state.compressed_current..4097];
    decompressed_bytes.extend_from_slice(bytes);

    state.decompressed_current += 4096;
    state.compressed_current += 4096;
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
    if state.compressed_current < state.compressed_end {
        while i <= 7 {
            if state.compressed_current < state.compressed_end {
                decompress_token(&compressed_bytes, decompressed_bytes, &i, flag_byte, state);
                i += 1;
            } else {
                break;
            }
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
}
