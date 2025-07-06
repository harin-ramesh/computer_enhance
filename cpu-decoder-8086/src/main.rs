use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::usize;

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

        let displacement = i16::from_ne_bytes([inst[2], inst[3]]).to_string();
        if displacement == "0" {
            return Some((format!("[{}]", registers), 2));
        }
        return Some((format!("[{} + {}]", registers, displacement), 2))
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

    let displacement = i8::from_ne_bytes([inst[2]]).to_string();
    if displacement != "0" {
        return Some((format!("[{} + {}]", registers, displacement), 1))
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

    let displacement = i16::from_ne_bytes([inst[2], inst[3]]).to_string();
    let displacement = if displacement != "0" {
        displacement
    } else {
        "".to_string()
    };

    Some((format!("[{} + {}]", registers, displacement), 2))
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

fn decode_instruction(inst: &[u8]) {
    if inst.len() < 2 {
        println!(
            "{:<6} {:<25} :NOT ENOUGH BYTES",
            inst.len(),
            inst.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "),
        );
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


    // Print each instruction
    println!(
        "{:<6} {:<25} {}",
        inst[inst_length..].len(),
        inst.iter()
            .take(inst_length)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" "),
        decoded_inst.join("")
    );
    decode_instruction(&inst[inst_length..]); 
}

fn main() -> io::Result<()> {
    let path = Path::new("data/listing_0039_more_movs");
    let mut file = File::open(&path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    println!("{:<6} {:<25} {}", "Remain", "Hex Bytes", "Decoded Instruction");

    decode_instruction(&buffer);

    Ok(())
}
