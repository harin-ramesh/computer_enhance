use std::path::Path;
use std::fs::{self, File};
use std::process::Command;
use std::io::{self, Read, Write};

fn decode_reg(reg: u8, w: u8) -> Option<(String, usize)> {
    let reg = match (reg, w) {
        (0b00000000, 0b00000000) => "al",
        (0b00000000, 0b00000001) => "ax",
        (0b00000001, 0b00000000) => "cl",
        (0b00000001, 0b00000001) => "cx",
        (0b00000010, 0b00000000) => "dl",
        (0b00000010, 0b00000001) => "dx",
        (0b00000011, 0b00000000) => "bl",
        (0b00000011, 0b00000001) => "bx",
        (0b00000100, 0b00000000) => "ah",
        (0b00000100, 0b00000001) => "sp",
        (0b00000101, 0b00000000) => "ch",
        (0b00000101, 0b00000001) => "bp",
        (0b00000110, 0b00000000) => "dh",
        (0b00000110, 0b00000001) => "si",
        (0b00000111, 0b00000000) => "bh",
        (0b00000111, 0b00000001) => "di",
        _ => return None,
    };

    Some((reg.to_string(), 0))
}

fn decode_mod_00(inst: &[u8], mod_bits: u8, rm: u8) -> Option<(String, usize)> {
    let registers = match rm {
        0b000 => "bx + si".to_string(),
        0b001 => "bx + di".to_string(),
        0b010 => "bp + si".to_string(),
        0b011 => "bp + di".to_string(),
        0b100 => "si".to_string(),
        0b101 => "di".to_string(),
        0b110 => "bp".to_string(),
        0b111 => "bx".to_string(),
        _ => return None,
    };

    if rm == 0b110 && mod_bits == 0b00 {
        let disp_size = if mod_bits == 0b00 { 0 } else { 2 };
        if inst.len() < 2 + disp_size {
            return None
        }

        let displacement = i16::from_ne_bytes([inst[2], inst[3]]);
        return Some((format!("[{}]", displacement), 2))
    }

    Some((format!("[{}]", registers), 0))
}

fn decode_mod_01(inst: &[u8], rm: u8) -> Option<(String, usize)> {
    let registers = match rm {
        0b000 => "bx + si".to_string(),
        0b001 => "bx + di".to_string(),
        0b010 => "bp + si".to_string(),
        0b011 => "bp + di".to_string(),
        0b100 => "si".to_string(),
        0b101 => "di".to_string(),
        0b110 => "bp".to_string(),
        0b111 => "bx".to_string(),
        _ => return None,
    };

    let displacement = i8::from_ne_bytes([inst[2]]);
    if displacement != 0 {
        if displacement > 0 {
            Some((format!("[{} + {}]", registers, displacement), 1))
        } else {
            Some((format!("[{} - {}]", registers, displacement.abs()), 1))
        }
    } else {
        return Some((format!("[{}]", registers), 1))
    }
}

fn decode_mod_10(inst: &[u8], rm: u8) -> Option<(String, usize)> {
    let registers = match rm {
        0b000 => "bx + si".to_string(),
        0b001 => "bx + di".to_string(),
        0b010 => "bp + si".to_string(),
        0b011 => "bp + di".to_string(),
        0b100 => "si".to_string(),
        0b101 => "di".to_string(),
        0b110 => "bp".to_string(),
        0b111 => "bx".to_string(),
        _ => return None,
    };

    let displacement = i16::from_ne_bytes([inst[2], inst[3]]);
    if displacement != 0 {
        if displacement > 0 {
            Some((format!("[{} + {}]", registers, displacement), 2))
        } else {
            Some((format!("[{} - {}]", registers, displacement.abs()), 2))
        }
    } else {
        Some((format!("[{}]", registers), 2))
    }
}

fn decode_registers(inst: &[u8], w: u8, mod_bits: u8, rm: u8) -> Option<(String, usize)> {
    match mod_bits {
        0b00 => decode_mod_00(inst, mod_bits, rm),
        0b01 => decode_mod_01(inst, rm),
        0b10 => decode_mod_10(inst, rm),
        0b11 => decode_reg(rm, w),
        _ => None,
    }
}

fn decode_instruction(inst: &[u8], output: &mut File) {
    if inst.len() < 2 {
        return;
    }

    let mut decoded_inst = vec![];

    let first_byte = inst[0];
    let second_byte = inst[1];

    let opcode = first_byte >> 2;
    let mut inst_length = 0;

    match opcode {
        0b100010 => {
            decoded_inst.push("mov ".to_string());

            let d = (first_byte >> 1) & 0b00000001;
            let w = first_byte & 0b00000001; 

            let mod_bits = second_byte >> 6;
            let reg = (second_byte >> 3) & 0b00000111;
            let rm = second_byte & 0b00000111; 

            if d == 1 {
                let (operand, _length) = decode_reg(reg, w).unwrap();
                decoded_inst.push(operand);
                decoded_inst.push(", ".to_string());
                let (operand, length) = decode_registers(inst, w, mod_bits, rm).unwrap();
                decoded_inst.push(operand);
                inst_length = 2 + length;
            } else {
                let (operand, length) = decode_registers(inst, w, mod_bits, rm).unwrap();
                decoded_inst.push(operand);
                decoded_inst.push(", ".to_string());
                inst_length = 2 + length;
                let (operand, _length) = decode_reg(reg, w).unwrap();
                decoded_inst.push(operand);
            }
        },
        _ => {
            let opcode = first_byte >> 4;
            match opcode {
                0b1011 => {
                    decoded_inst.push("mov ".to_string());
                    let reg = (first_byte & 0b00000111) as u8;
                    let w = (first_byte >> 3) & 0b00000001;

                    let (operand, _length) = decode_reg(reg, w).unwrap();
                    decoded_inst.push(operand);
                    let disp_value = if w == 0 {
                        inst_length = 2;
                        format!(", {}", i8::from_ne_bytes([inst[1]]))
                    } else {
                        inst_length = 3;
                        format!(", {}", i16::from_ne_bytes([inst[1], inst[2]]))
                    };
                    decoded_inst.push(disp_value);
                },
                _ => {
                    println!("Unknown opcode: {:06b}, first_byte: {:06b}", opcode, first_byte);
                    return;
                },
            }
        },
    }

    let line = format!("{}\n", decoded_inst.join(""));
    output.write_all(line.as_bytes()).unwrap();

    decode_instruction(&inst[inst_length..], output);
}

fn main() -> io::Result<()> {
    let dir_path = Path::new("data");

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let mut file = File::open(&path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            // Output filename: original + .asm
            let output_dir = Path::new("data/decode_asm");
            fs::create_dir_all(output_dir)?; // Ensure directory exists

            let file_stem = path.file_stem().unwrap(); // e.g. "mov_test"
            let mut asm_path = output_dir.join(file_stem);
            asm_path.set_extension("asm");

            let mut output = File::create(&asm_path)?;
            writeln!(
                output,
                "; Decoded instructions from: {}\n",
                path.display()
            )?;
            writeln!(
                output,
                "bits 16",
            )?;

            decode_instruction(&buffer, &mut output);

            // Compile the assembly file
            let bin_path = asm_path.with_extension("bin");

            let nasm_status = Command::new("nasm")
                .args(["-f", "bin", "-o"])
                .arg(&bin_path)
                .arg(&asm_path)
                .status()?;

            if !nasm_status.success() {
                eprintln!("x Failed to compile {}", asm_path.display());
                continue;
            }

            // Compare compiled binary with original
            let compiled = fs::read(&bin_path)?;
            let original = &buffer; // already read before
            let mut original = original.clone();

            // Only remove trailing newline byte if it exists
            if original.last() == Some(&0x0a) {
                original.pop();
            }
            if compiled == *original {
                println!("Match: {} matches original", bin_path.display());
            } else {
                println!("x Mismatch: {} differs from original", bin_path.display());
                
                // Show byte-by-byte difference for debugging
                println!("Original: {} bytes", original.len());
                println!("Compiled: {} bytes", compiled.len());
                
                let min_len = original.len().min(compiled.len());
                let _max_len = original.len().max(compiled.len());
                
                // Compare bytes that exist in both
                for i in 0..min_len {
                    if original[i] != compiled[i] {
                        println!("  Byte {}: original=0x{:02x}, compiled=0x{:02x}", i, original[i], compiled[i]);
                    }
                }
                
                // Show extra bytes in original
                if original.len() > compiled.len() {
                    for i in min_len..original.len() {
                        println!("  Byte {} (original only): 0x{:02x}", i, original[i]);
                    }
                }
                
                // Show extra bytes in compiled
                if compiled.len() > original.len() {
                    for i in min_len..compiled.len() {
                        println!("  Byte {} (compiled only): 0x{:02x}", i, compiled[i]);
                    }
                }    
            }
        }
    }

    Ok(())
}
