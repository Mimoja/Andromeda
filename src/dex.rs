
extern crate nom;
extern crate leb128;

use nom::*;
use std::convert::AsMut;
use std::str;


#[derive(Debug)]
pub enum EndianConstant {
    EndianConstant = 0x12345678,
    ReverseEndianConstant = 0x78563412,
}

#[derive(Debug)]
pub struct DexFile {
    header: DexHeader,
    method_ids: Vec<MethodID>,
    strings: Vec<String>,
    type_descriptors: Vec<u32>,
    proto_ids: Vec<ProtoID>,
    field_ids: Vec<FieldID>,
    class_defs: Vec<ClassDef>,
}

#[derive(Debug)]
pub struct DexHeader {
    magic: [u8; 4],
    version: [u8; 4],
    checksum: u32,
    signature: [u8; 20],
    file_size: u32,
    header_size: u32,
    endian_tag: EndianConstant,
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    data_size: u32,
    data_off: u32,
}

#[derive(Debug)]
pub struct MethodID {
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32,
}

#[derive(Debug)]
pub struct ProtoID {
    shorty_idx: u32,
    return_type_idx: u32,
    parameters_off: u32,
}

#[derive(Debug)]
pub struct FieldID {
    class_idx: u16,
    type_idx: u16,
    name_idx: u32,
}

#[derive(Debug)]
pub struct ClassDef {
    class_idx: u32,
    access_flags: u32,
    superclass_idx: u32,
    interfaces_off: u32,
    source_file_idx: u32,
    annotations_off: u32,
    class_data_off: u32,
    static_values_off: u32,
}


fn header_endian(input: &[u8]) -> IResult<&[u8], EndianConstant> {
    return match le_u32(input) {
        IResult::Done(r, 0x12345678) => IResult::Done(r, EndianConstant::EndianConstant),
        IResult::Done(r, 0x78563412) => IResult::Done(r, EndianConstant::ReverseEndianConstant),
        IResult::Done(r, o) => {
            println!("Unknown Endianes : 0x{:x}", o);
            IResult::Done(r, EndianConstant::EndianConstant)
        }
        _ => IResult::Error(Err::Code(ErrorKind::Custom(2))),
    };
}

named!(header(&[u8])->DexHeader, chain!(
       	magic: tag!("dex\n")~
		version: take!(4)~
		checksum: le_u32~
		signature: take!(20)~
		file_size: le_u32~
		header_size: le_u32~ // represents 0x70
		endian_tag: header_endian~
		link_size: le_u32~
		link_off: le_u32~
		map_off: le_u32~
		string_ids_size: le_u32~
		string_ids_off: le_u32~
		type_ids_size: le_u32~
		type_ids_off: le_u32~
		proto_ids_size: le_u32~
		proto_ids_off: le_u32~
		field_ids_size: le_u32~
		field_ids_off: le_u32~
		method_ids_size: le_u32~
		method_ids_off: le_u32~
		class_defs_size: le_u32~
		class_defs_off: le_u32~
		data_size: le_u32~
		data_off: le_u32,
		|| DexHeader{
		    magic:as_array(&magic[0..4]),
	        version:as_array(&version[0..4]),
	        checksum:checksum,
	        signature:as_array(&signature[0..20]),
	        file_size:file_size,
	        header_size:header_size,
	        endian_tag:endian_tag,
	        link_size:link_size,
	        link_off:link_off,
	        map_off:map_off,
	        string_ids_size:string_ids_size,
	        string_ids_off:string_ids_off,
	        type_ids_size:type_ids_size,
	        type_ids_off:type_ids_off,
	        proto_ids_size:proto_ids_size,
	        proto_ids_off:proto_ids_off,
	        field_ids_size:field_ids_size,
	        field_ids_off:field_ids_off,
	        method_ids_size:method_ids_size,
	        method_ids_off:method_ids_off,
	        class_defs_size:class_defs_size,
	        class_defs_off:class_defs_off,
	        data_size:data_size,
	        data_off:data_off,
	        })
	   );


named!(proto_id(&[u8]) -> ProtoID, chain!(
		shorty_idx: le_u32~
	    return_type_idx: le_u32~
	    parameters_off : le_u32,
		|| ProtoID {
			shorty_idx:shorty_idx,
			return_type_idx:return_type_idx,
			parameters_off:parameters_off
		})
);

named!(method_id(&[u8]) -> MethodID, chain!(
		class_idx : le_u16 ~
		proto_idx : le_u16 ~
		name_idx : le_u32 ,
	|| MethodID {
		class_idx:class_idx,
		proto_idx:proto_idx,
		name_idx:name_idx
	})
);

named!(field_id(&[u8]) -> FieldID, chain!(
		class_idx : le_u16 ~
		type_idx : le_u16 ~
		name_idx : le_u32 ,
	|| FieldID {
		class_idx:class_idx,
		type_idx:type_idx,
		name_idx:name_idx
	})
);

named!(class_def(&[u8]) -> ClassDef, chain!(
	    class_idx: le_u32 ~
	    access_flags: le_u32 ~
	    superclass_idx: le_u32 ~
	    interfaces_off: le_u32 ~
	    source_file_idx: le_u32 ~
	    annotations_off: le_u32 ~
	    class_data_off: le_u32 ~
	    static_values_off: le_u32,
		|| ClassDef {
		    class_idx: class_idx,
		    access_flags: access_flags,
		    superclass_idx: superclass_idx,
		    interfaces_off: interfaces_off,
		    source_file_idx: source_file_idx,
		    annotations_off: annotations_off,
		    class_data_off: class_data_off,
		    static_values_off: static_values_off,
		})
);

fn fields(input: &[u8], count: u32) -> IResult<&[u8], Vec<FieldID>> {
    let mut rest = input;
    let mut list: Vec<FieldID> = vec![];
    for _ in 0..count {
        let entry = field_id(rest);
        match entry {
            IResult::Done(i, o) => {
                rest = i;
                list.push(o);
                continue;
            }
            _ => return IResult::Error(Err::Code(ErrorKind::Custom(1))),
        }
    }
    return IResult::Done(rest, list);
}


fn methods(input: &[u8], count: u32) -> IResult<&[u8], Vec<MethodID>> {
    let mut rest = input;
    let mut list: Vec<MethodID> = vec![];
    for _ in 0..count {
        let entry = method_id(rest);
        match entry {
            IResult::Done(i, o) => {
                rest = i;
                list.push(o);
                continue;
            }
            _ => return IResult::Error(Err::Code(ErrorKind::Custom(1))),
        }
    }
    return IResult::Done(rest, list);
}

fn protos(input: &[u8], count: u32) -> IResult<&[u8], Vec<ProtoID>> {
    let mut rest = input;
    let mut list: Vec<ProtoID> = vec![];
    for _ in 0..count {
        let entry = proto_id(rest);
        match entry {
            IResult::Done(i, o) => {
                rest = i;
                list.push(o);
                continue;
            }
            _ => return IResult::Error(Err::Code(ErrorKind::Custom(0))),
        }
    }
    return IResult::Done(rest, list);
}


fn string_ids(input: &[u8], count: u32) -> IResult<&[u8], Vec<u32>> {
    let mut rest = input;
    let mut list: Vec<u32> = vec![];
    for _ in 0..count {
        let entry = le_u32(rest);
        match entry {
            IResult::Done(i, o) => {
                rest = i;
                list.push(o);
                continue;
            }
            _ => return IResult::Error(Err::Code(ErrorKind::Custom(0))),
        }
    }
    return IResult::Done(rest, list);
}


fn type_ids(input: &[u8], count: u32) -> IResult<&[u8], Vec<u32>> {
    let mut rest = input;
    let mut list: Vec<u32> = vec![];
    for _ in 0..count {
        let entry = le_u32(rest);
        match entry {
            IResult::Done(i, o) => {
                rest = i;
                list.push(o);
                continue;
            }
            _ => return IResult::Error(Err::Code(ErrorKind::Custom(0))),
        }
    }
    return IResult::Done(rest, list);
}

fn classes(input: &[u8], count: u32) -> IResult<&[u8], Vec<ClassDef>> {
    let mut rest = input;
    let mut list: Vec<ClassDef> = vec![];
    for _ in 0..count {
        let entry = class_def(rest);
        match entry {
            IResult::Done(i, o) => {
                rest = i;
                list.push(o);
                continue;
            }
            _ => return IResult::Error(Err::Code(ErrorKind::Custom(0))),
        }
    }
    return IResult::Done(rest, list);
}


pub fn parse(data: Vec<u8>) -> Option<DexFile> {
    let input = data.as_slice();
    let h: DexHeader;
    let s: Vec<String> = vec![];
    let t: Vec<u32>;
    let p: Vec<ProtoID>;
    let f: Vec<FieldID>;
    let m: Vec<MethodID>;
    let c: Vec<ClassDef>;


    match header(input) {
        IResult::Done(_, o) => h = o,
        _ => return None,
    }

    let si;
    let string_id_off = h.string_ids_off as usize;
    match string_ids(&input[string_id_off..], h.string_ids_size) {
        IResult::Done(_, o) => si = o,
        _ => return None,
    }

    for i in 0..h.string_ids_size {
        let off = si[i as usize] as usize;
        let mut readable = &input[off..];
        let val = leb128::read::unsigned(&mut readable).expect("Should read number") as usize;
        let off = off + 1;
        let data = &input[off..off + val];
        let s = str::from_utf8(data).unwrap();
    }


    let method_off = h.method_ids_off as usize;
    match methods(&input[method_off..], h.method_ids_size) {
        IResult::Done(_, o) => m = o,
        _ => return None,
    }


    let proto_off = h.proto_ids_off as usize;
    match protos(&input[proto_off..], h.proto_ids_size) {
        IResult::Done(_, o) => p = o,
        _ => return None,
    }


    let field_off = h.field_ids_off as usize;
    match fields(&input[field_off..], h.field_ids_size) {
        IResult::Done(_, o) => f = o,
        _ => return None,
    }

    let type_off = h.type_ids_off as usize;
    match type_ids(&input[type_off..], h.type_ids_size) {
        IResult::Done(_, o) => t = o,
        _ => return None,
    }

    let class_def_off = h.class_defs_off as usize;
    match classes(&input[class_def_off..], h.class_defs_size) {
        IResult::Done(_, o) => c = o,
        _ => return None,
    }

    return Some(DexFile {
        header: h,
        method_ids: m,
        strings: s,
        proto_ids: p,
        type_descriptors: t,
        field_ids: f,
        class_defs: c,
    });
}

fn as_array<A, T>(slice: &[T]) -> A
    where A: Sized + Default + AsMut<[T]>,
          T: Clone
{
    let mut array = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut array).clone_from_slice(slice);
    return array;
}
