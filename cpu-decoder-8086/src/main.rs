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

fn decode_mod_00(inst: &[u8], rm: u8) -> Option<(String, usize)> {

    if rm == 0b110 {
        let displacement = i16::from_ne_bytes([inst[2], inst[3]]);
        return Some((format!("[{}]", displacement), 2))
    }

    let registers = match rm {
        0b000 => "bx + si".to_string(),
        0b001 => "bx + di".to_string(),
        0b010 => "bp + si".to_string(),
        0b011 => "bp + di".to_string(),
        0b100 => "si".to_string(),
        0b101 => "di".to_string(),
//      0b110 => "bp".to_string(),
        0b111 => "bx".to_string(),
        _ => return None,
    };


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
        0b00 => decode_mod_00(inst, rm),
        0b01 => decode_mod_01(inst, rm),
        0b10 => decode_mod_10(inst, rm),
        0b11 => decode_reg(rm, w),
        _ => None,
    }
}

#[allow(unused_assignments)]
fn decode_instruction(inst: &[u8], output: &mut File) {
    if inst.len() < 2 {
        return;
    }
    let opcode = inst[0];
    let mut decoded_inst = vec![];
    let mut inst_length = 0;

    match opcode {
        0b01110000..=0b01111111 => {
            let mnem = match opcode {
                0b01110100 => "je",
                0b01111100 => "jl",
                0b01111110 => "jle",
                0b01110010 => "jb",
                0b01110110 => "jbe",
                0b01111010 => "jp",
                0b01110000 => "jo",
                0b01111000 => "js",
                0b01110101 => "jne",
                0b01111101 => "jnl",
                0b01111111 => "jnle",
                0b01110011 => "jnb",
                0b01110111 => "jnbe",
                0b01111011 => "jnp",
                0b01110001 => "jno",
                0b01111001 => "jns",
                _ => unreachable!(),
            };
            let offset = inst[1] as i8;
            decoded_inst.push(format!("{} {}", mnem, offset));
            inst_length += 2;
        },
        0b11100010 => {
            decoded_inst.push(format!("loop {}", inst[1] as i8));
            inst_length += 2;
        },
        0b11100001 => {
            decoded_inst.push(format!("loopz {}", inst[1] as i8));
            inst_length += 2;
        },
        0b11100000 => {
            decoded_inst.push(format!("loopnz {}", inst[1] as i8));
            inst_length += 2;
        },
        0b11100011 => {
            decoded_inst.push(format!("jcxz {}", inst[1] as i8));
            inst_length += 2;
        },
        _ => {
            let first_byte = inst[0];
            let second_byte = inst[1];

            let opcode = first_byte >> 2;

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
                0b000000 | 0b001010 | 0b001110 => {
                    let mnemonic = match (first_byte >> 2) & 0b111111 {
                        0b000000 => "add ",
                        0b001010 => "sub ",
                        0b001110 => "cmp ",
                        _ => unreachable!(),
                    };

                    decoded_inst.push(mnemonic.to_string());

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
                0b100000 => {
                    // Extract s and w bits
                    let s = (first_byte >> 1) & 0b1;
                    let w = first_byte & 0b1;

                    // Extract mod-reg-r/m fields from second byte
                    let mod_bits = second_byte >> 6;
                    let reg_opcode = (second_byte >> 3) & 0b111;
                    let rm = second_byte & 0b111;

                    // Determine mnemonic (ADD, SUB, CMP)
                    let mnemonic = match reg_opcode {
                        0b000 => "add ",
                        0b101 => "sub ",
                        0b111 => "cmp ",
                        _ => unreachable!("Unsupported ALU opcode in 100000 group"),
                    };
                    decoded_inst.push(mnemonic.to_string());

                    // Decode the operand (register or memory)
                    let (operand, disp_len) = decode_registers(inst, w, mod_bits, rm).unwrap();

                    // Determine where the immediate value starts
                    let imm_index = 2 + disp_len;

                    // Compute immediate value and total length
                    let (immediate_val, imm_len) = if s == 1 && w == 1 {
                        // 8-bit immediate sign-extended to 16-bit
                        let imm = inst[imm_index] as i8 as i16;
                        (imm.to_string(), 1)
                    } else if w == 1 {
                        // 16-bit immediate
                        let imm = i16::from_le_bytes([inst[imm_index], inst[imm_index + 1]]);
                        (imm.to_string(), 2)
                    } else {
                        // 8-bit immediate
                        let imm = inst[imm_index] as i8;
                        (imm.to_string(), 1)
                    };

                    // Decide whether to show byte/word prefix
                    let size_prefix = if mod_bits == 0b11 {
                        // Register operand — no prefix needed
                        "".to_string()
                    } else if w == 1 {
                        "word ".to_string()
                    } else {
                        "byte ".to_string()
                    };

                    // Final operand formatting
                    decoded_inst.push(format!("{}{}", size_prefix, operand));
                    decoded_inst.push(", ".to_string());
                    decoded_inst.push(immediate_val);

                    // Total instruction length = 2 + disp + immediate length
                    inst_length = imm_index + imm_len;
                }
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
                            let opcode = first_byte >> 1;
                            match opcode {
                                0b0000010 | 0b0010110 | 0b0011110 => {
                                    let mnemonic = match opcode {
                                        0b0000010 => "add ",
                                        0b0010110 => "sub ",
                                        0b0011110 => "cmp ",
                                        _ => unreachable!(),
                                    };
                                    decoded_inst.push(mnemonic.to_string());

                                    let w = (first_byte & 0b00000001) as u8;

                                    let disp_value = if w == 0 {
                                        inst_length = 2;
                                        format!("al, {}", i8::from_ne_bytes([inst[1]]))
                                    } else {
                                        inst_length = 3;
                                        format!("ax, {}", i16::from_ne_bytes([inst[1], inst[2]]))
                                    };
                                    decoded_inst.push(disp_value);
                                },
                                0b1010000 => {
                                    decoded_inst.push("mov ".to_string());
                                    let w = (first_byte & 0b00000001) as u8;

                                    let disp_value = if w == 0 {
                                        inst_length = 2;
                                        format!("al, [{}]", i8::from_ne_bytes([inst[1]]))
                                    } else {
                                        inst_length = 3;
                                        format!("ax, [{}]", i16::from_ne_bytes([inst[1], inst[2]]))
                                    };
                                    decoded_inst.push(disp_value);
                                },
                                0b1010001 => {
                                    decoded_inst.push("mov ".to_string());
                                    let w = (first_byte & 0b00000001) as u8;

                                    let disp_value = if w == 0 {
                                        inst_length = 2;
                                        format!("[{}], al", i8::from_ne_bytes([inst[1]]))
                                    } else {
                                        inst_length = 3;
                                        format!("[{}], ax", i16::from_ne_bytes([inst[1], inst[2]]))
                                    };
                                    decoded_inst.push(disp_value);
                                },
                                0b1100011 => {
                                    decoded_inst.push("mov ".to_string());

                                    let d = (first_byte >> 1) & 0b1;
                                    let w = first_byte & 0b1;

                                    let mod_bits = second_byte >> 6;
                                    let rm = second_byte & 0b00000111;

                                    // Operand decoding stays same
                                    let (operand, disp_len) = decode_registers(inst, w, mod_bits, rm).unwrap();

                                    // Compute where immediate starts
                                    let imm_index = 2 + disp_len;

                                    let immidiate_val = if w == 0 {
                                        format!("byte {}", i8::from_ne_bytes([inst[imm_index]]))
                                    } else {
                                        format!(
                                            "word {}",
                                            i16::from_le_bytes([inst[imm_index], inst[imm_index + 1]])
                                        )
                                    };

                                    // Order based on direction bit
                                    if d == 1 {
                                        decoded_inst.push(operand);
                                        decoded_inst.push(", ".to_string());
                                        decoded_inst.push(immidiate_val);
                                    } else {
                                        decoded_inst.push(immidiate_val);
                                        decoded_inst.push(", ".to_string());
                                        decoded_inst.push(operand);
                                    }

                                    // Final instruction length
                                    inst_length = imm_index + if w == 0 { 1 } else { 2 };
                                }
                                _ => {
                                    println!("Unknown opcode: {:06b}, first_byte: {:08b}", opcode, first_byte);
                                    return;
                                },
                            }
                        },
                    }
                },
            }
        }
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
