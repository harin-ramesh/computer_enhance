use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn decode_register(reg: u8, w: u8) -> String {
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
        _ => "unknown",
    };
    reg.to_string()
}

fn decode_instruction(inst: &[u8]) {
    if inst.len() < 2 {
        println!("Instruction too short");
        return;
    }

    let mut decoded_inst = vec![];

    let first_byte = inst[0];
    let second_byte = inst[1];

    let opcode = first_byte >> 2;
    match opcode {
        0b100010 => {
            decoded_inst.push("mov".to_string());
        },
        _ => {
            println!("Unknown opcode: {:06b}", opcode);
            return;
        },
    }

    let mod_bits = second_byte >> 6;
    let w = first_byte & 0b00000001; 

    match mod_bits {
        0b11 => {
            let reg = second_byte & 0b00000111; 
            decoded_inst.push(decode_register(reg, w));

            let reg = (second_byte >> 3) & 0b0000_0111;
            decoded_inst.push(decode_register(reg, w));
        },
        _ => {
            println!("Other addressing mode");
            return;
        }
    }
    
    println!("{}", decoded_inst.join(" "));

    decode_instruction(&inst[2..]); 
}

fn main() -> io::Result<()> {
    let path = Path::new("data/listing_0038_many_register_mov");
    let file = File::open(&path)?;
    let reader = io::BufReader::new(file);

    for inst in reader.split(b'\n') {
        decode_instruction(&inst?);
    }

    Ok(())
}
