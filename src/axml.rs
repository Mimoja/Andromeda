extern crate byteorder;

use std::io::Cursor;
use std::io::SeekFrom;
use std::io::Seek;
use self::byteorder::{ReadBytesExt, LittleEndian, BigEndian};
use std::u16;
use std::vec::*;

#[derive(Debug)]
enum RES_TYPE {
    RES_NULL_TYPE,
    RES_STRING_POOL_TYPE,
    RES_TABLE_TYPE,
    RES_XML_TYPE,

    // Chunk types in RES_XML_TYPE
    RES_XML_FIRST_CHUNK_TYPE,
    RES_XML_START_NAMESPACE_TYPE,
    RES_XML_END_NAMESPACE_TYPE,
    RES_XML_START_ELEMENT_TYPE,
    RES_XML_END_ELEMENT_TYPE,
    RES_XML_CDATA_TYPE,
    RES_XML_LAST_CHUNK_TYPE,
    // This contains a uint32_t array mapping strings in the string
    // pool back to resource identifiers.  It is optional.
    RES_XML_RESOURCE_MAP_TYPE,

    // Chunk types in RES_TABLE_TYPE
    RES_TABLE_PACKAGE_TYPE,
    RES_TABLE_TYPE_TYPE,
    RES_TABLE_TYPE_SPEC_TYPE,
}
// enum {
// Contains no data.
// TYPE_NULL = 0x00,
// The 'data' holds a ResTable_ref, a reference to another resource
// table entry.
// TYPE_REFERENCE = 0x01,
// The 'data' holds an attribute resource identifier.
// TYPE_ATTRIBUTE = 0x02,
// The 'data' holds an index into the containing resource table's
// global value string pool.
// TYPE_STRING = 0x03,
// The 'data' holds a single-precision floating point number.
// TYPE_FLOAT = 0x04,
// The 'data' holds a complex number encoding a dimension value,
// such as "100in".
// TYPE_DIMENSION = 0x05,
// The 'data' holds a complex number encoding a fraction of a
// container.
// TYPE_FRACTION = 0x06,
//
// Beginning of integer flavors...
// TYPE_FIRST_INT = 0x10,
//
// The 'data' is a raw integer value of the form n..n.
// TYPE_INT_DEC = 0x10,
// The 'data' is a raw integer value of the form 0xn..n.
// TYPE_INT_HEX = 0x11,
// The 'data' is either 0 or 1, for input "false" or "true" respectively.
// TYPE_INT_BOOLEAN = 0x12,
//
// Beginning of color integer flavors...
// TYPE_FIRST_COLOR_INT = 0x1c,
//
// The 'data' is a raw integer value of the form #aarrggbb.
// TYPE_INT_COLOR_ARGB8 = 0x1c,
// The 'data' is a raw integer value of the form #rrggbb.
// TYPE_INT_COLOR_RGB8 = 0x1d,
// The 'data' is a raw integer value of the form #argb.
// TYPE_INT_COLOR_ARGB4 = 0x1e,
// The 'data' is a raw integer value of the form #rgb.
// TYPE_INT_COLOR_RGB4 = 0x1f,
//
// ...end of integer flavors.
// TYPE_LAST_COLOR_INT = 0x1f,
//
// ...end of integer flavors.
// TYPE_LAST_INT = 0x1f
// };
//   enum {
// Where the unit type information is.  This gives us 16 possible
// types, as defined below.
// COMPLEX_UNIT_SHIFT = 0,
// COMPLEX_UNIT_MASK = 0xf,
//
// TYPE_DIMENSION: Value is raw pixels.
// COMPLEX_UNIT_PX = 0,
// TYPE_DIMENSION: Value is Device Independent Pixels.
// COMPLEX_UNIT_DIP = 1,
// TYPE_DIMENSION: Value is a Scaled device independent Pixels.
// COMPLEX_UNIT_SP = 2,
// TYPE_DIMENSION: Value is in points.
// COMPLEX_UNIT_PT = 3,
// TYPE_DIMENSION: Value is in inches.
// COMPLEX_UNIT_IN = 4,
// TYPE_DIMENSION: Value is in millimeters.
// COMPLEX_UNIT_MM = 5,
//
// TYPE_FRACTION: A basic fraction of the overall size.
// COMPLEX_UNIT_FRACTION = 0,
// TYPE_FRACTION: A fraction of the parent size.
// COMPLEX_UNIT_FRACTION_PARENT = 1,
//
// Where the radix information is, telling where the decimal place
// appears in the mantissa.  This give us 4 possible fixed point
// representations as defined below.
// COMPLEX_RADIX_SHIFT = 4,
// COMPLEX_RADIX_MASK = 0x3,
//
// The mantissa is an integral number -- i.e., 0xnnnnnn.0
// COMPLEX_RADIX_23p0 = 0,
// The mantissa magnitude is 16 bits -- i.e, 0xnnnn.nn
// COMPLEX_RADIX_16p7 = 1,
// The mantissa magnitude is 8 bits -- i.e, 0xnn.nnnn
// COMPLEX_RADIX_8p15 = 2,
// The mantissa magnitude is 0 bits -- i.e, 0x0.nnnnnn
// COMPLEX_RADIX_0p23 = 3,
//
// Where the actual value is.  This gives us 23 bits of
// precision.  The top bit is the sign.
// COMPLEX_MANTISSA_SHIFT = 8,
// COMPLEX_MANTISSA_MASK = 0xffffff
// };


struct res_chunk_header {
    position: u32,
    res_type: u16,
    res_enum_type: RES_TYPE,
    header_size: u16,
    total_size: u32,
}
impl res_chunk_header {
    fn new(reader: &mut Cursor<&Vec<u8>>) -> res_chunk_header {
        let pos = reader.position();
        let c_type = reader.read_u16::<LittleEndian>().unwrap();
        let h_size = reader.read_u16::<LittleEndian>().unwrap();
        let t_size = reader.read_u32::<LittleEndian>().unwrap();

        let e_type = match c_type {
            0x0000 => RES_TYPE::RES_NULL_TYPE,
            0x0001 => RES_TYPE::RES_STRING_POOL_TYPE,
            0x0002 => RES_TYPE::RES_TABLE_TYPE,
            0x0003 => RES_TYPE::RES_XML_TYPE,
            0x0100 => RES_TYPE::RES_XML_START_NAMESPACE_TYPE,
            0x0101 => RES_TYPE::RES_XML_END_NAMESPACE_TYPE,
            0x0102 => RES_TYPE::RES_XML_START_ELEMENT_TYPE,
            0x0103 => RES_TYPE::RES_XML_END_ELEMENT_TYPE,
            0x0180 => RES_TYPE::RES_XML_RESOURCE_MAP_TYPE,
            0x0200 => RES_TYPE::RES_TABLE_PACKAGE_TYPE,
            0x0201 => RES_TYPE::RES_TABLE_TYPE_TYPE,
            0x0202 => RES_TYPE::RES_TABLE_TYPE_SPEC_TYPE,
            _ => RES_TYPE::RES_NULL_TYPE,

        };

        return res_chunk_header {
            position: pos as u32,
            res_type: c_type,
            res_enum_type: e_type,
            header_size: h_size,
            total_size: t_size,
        };
    }
}
struct AXMLNode_element_attributes {
    ns: u32,
    name: u32,
    raw_value: u32,
    size: u16,
    zero: u8,
    data_type: u8,
    data: u32,
}

enum AXMLNode_content {
    AXMLNode_namespace {
        lineNumber: u32,
        comment: u32,
        prefix: u32,
        uri: u32,
    },

    AXMLNode_element {
        lineNumber: u32,
        comment: u32,
        ns: u32,
        name: u32,
        attribute_start: u16,
        attribute_size: u16,
        attribute_count: u16,
        id_index: u16,
        class_index: u16,
        style_index: u16,
        attributes: Vec<AXMLNode_element_attributes>,
    },
    AXMLNode_element_end {
        lineNumber: u32,
        comment: u32,
        ns: u32,
        name: u32,
    },
}

struct AXMLNode {
    children: Vec<AXMLNode>,
    content: Option<AXMLNode_content>,
    closing: Option<AXMLNode_content>,
    node_type: RES_TYPE,
}

struct res_chunk_root {
    header: res_chunk_header,
    strings: Vec<String>,
    resource_map: Vec<u32>,
    axml: Vec<AXMLNode>,
}

impl res_chunk_root {
    fn new(mut reader: &mut Cursor<&Vec<u8>>) -> res_chunk_root {

        let h = res_chunk_header::new(reader);

        let mut root = res_chunk_root {
            header: h,
            strings: vec![],
            resource_map: vec![],
            axml: vec![],
        };

        while reader.position() < root.header.total_size as u64 {
            let node = res_chunk_header::new(&mut reader);
            match node.res_enum_type {
                RES_TYPE::RES_STRING_POOL_TYPE => root.read_string_pool(reader, node),
                RES_TYPE::RES_XML_RESOURCE_MAP_TYPE => root.read_resource_map(reader, node),
                RES_TYPE::RES_XML_START_NAMESPACE_TYPE => root.read_root_node(reader, node),
                _ => panic!("Unimplemented AXML Tag!"),

            }
        }

        return root;
    }

    fn read_namespace_contents(&mut self,
                               mut reader: &mut Cursor<&Vec<u8>>,
                               node: res_chunk_header)
                               -> AXMLNode {

        let lineNumber: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let comment: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let prefix: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let uri: u32 = reader.read_u32::<LittleEndian>().unwrap();

        let mut namespace = AXMLNode_content::AXMLNode_namespace {
            lineNumber: lineNumber,
            comment: comment,
            prefix: prefix,
            uri: uri,
        };

        let mut node = AXMLNode {
            children: vec![],
            closing: None,
            content: Some(namespace),
            node_type: node.res_enum_type,
        };
        return node;
    }

    fn read_namespace_node(&mut self,
                           mut reader: &mut Cursor<&Vec<u8>>,
                           node: res_chunk_header)
                           -> AXMLNode {


        let mut root: AXMLNode = self.read_namespace_contents(reader, node);

        loop {
            let node = res_chunk_header::new(&mut reader);
            let nextNode: u64 = (node.position + node.total_size) as u64;
            match node.res_enum_type {
                RES_TYPE::RES_XML_START_NAMESPACE_TYPE => {
                    let mut namespace_node = self.read_namespace_node(reader, node);
                    root.children.push(namespace_node);
                }
                RES_TYPE::RES_XML_START_ELEMENT_TYPE => {
                    let mut element_node = self.read_element_node(reader, node);
                    root.children.push(element_node);
                }
                RES_TYPE::RES_XML_END_NAMESPACE_TYPE => {
                    let endnode = self.read_namespace_contents(reader, node);
                    root.closing = Some(endnode.content.unwrap());
                    break;
                }
                _ => {}
            }
        }
        return root;
    }

    fn read_element_end_node(&mut self,
                             mut reader: &mut Cursor<&Vec<u8>>,
                             node: res_chunk_header)
                             -> AXMLNode_content {
        let lineNumber: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let comment: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let ns: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let name: u32 = reader.read_u32::<LittleEndian>().unwrap();

        let end_element = AXMLNode_content::AXMLNode_element_end {
            lineNumber: lineNumber,
            comment: comment,
            ns: ns,
            name: name,
        };
        return end_element;
    }

    fn read_element_attribute(&mut self,
                              mut reader: &mut Cursor<&Vec<u8>>)
                              -> AXMLNode_element_attributes {

        let ns: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let name: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let raw_value: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let size: u16 = reader.read_u16::<LittleEndian>().unwrap();
        let data_type = reader.read_u16::<BigEndian>().unwrap() as u8;
        let data: u32 = reader.read_u32::<LittleEndian>().unwrap();

        return AXMLNode_element_attributes {
            ns: ns,
            name: name,
            raw_value: raw_value,
            size: size,
            zero: 0,
            data_type: data_type,
            data: data,
        };
    }

    fn read_element_node(&mut self,
                         mut reader: &mut Cursor<&Vec<u8>>,
                         node: res_chunk_header)
                         -> AXMLNode {

        let pos = reader.position();
        let lineNumber: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let comment: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let ns: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let name: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let attribute_start: u16 = reader.read_u16::<LittleEndian>().unwrap();
        let attribute_size: u16 = reader.read_u16::<LittleEndian>().unwrap();
        let attribute_count: u16 = reader.read_u16::<LittleEndian>().unwrap();
        let id_index: u16 = reader.read_u16::<LittleEndian>().unwrap();
        let class_index: u16 = reader.read_u16::<LittleEndian>().unwrap();
        let style_index: u16 = reader.read_u16::<LittleEndian>().unwrap();

        if attribute_size != 0x14 {
            panic!("Attribute size not where it is expected. please report as bug");
        }


        let mut attrs: Vec<AXMLNode_element_attributes> = vec![];

        for i in 0..attribute_count {
            let attr = self.read_element_attribute(reader);
            attrs.push(attr);
        }

        let mut element = AXMLNode_content::AXMLNode_element {
            lineNumber: lineNumber,
            comment: comment,
            ns: ns,
            name: name,
            attribute_start: attribute_start,
            attribute_size: attribute_size,
            attribute_count: attribute_count,
            id_index: id_index,
            class_index: class_index,
            style_index: style_index,
            attributes: attrs,
        };

        let mut root = AXMLNode {
            children: vec![],
            closing: None,
            content: Some(element),
            node_type: node.res_enum_type,
        };



        let nextNode: u64 = (node.position + node.total_size) as u64;
        reader.seek(SeekFrom::Start(nextNode));

        loop {
            let node = res_chunk_header::new(&mut reader);
            let nextNode: u64 = (node.position + node.total_size) as u64;

            match node.res_enum_type {
                RES_TYPE::RES_XML_START_NAMESPACE_TYPE => {
                    let mut namespace_node = self.read_namespace_node(reader, node);
                    root.children.push(namespace_node);
                }

                RES_TYPE::RES_XML_START_ELEMENT_TYPE => {
                    let mut element_node = self.read_element_node(reader, node);
                    root.children.push(element_node);
                }

                RES_TYPE::RES_XML_END_ELEMENT_TYPE => {
                    let end_element = self.read_element_end_node(reader, node);
                    root.closing = Some(end_element);
                    reader.seek(SeekFrom::Start(nextNode));
                    break;
                }
                _ => {}
            }
        }
        return root;
    }

    fn read_root_node(&mut self, mut reader: &mut Cursor<&Vec<u8>>, node: res_chunk_header) {

        let mut namespace_node = self.read_namespace_node(reader, node);
        self.axml.push(namespace_node);

    }


    fn read_resource_map(&mut self, reader: &mut Cursor<&Vec<u8>>, node: res_chunk_header) {

        let attr_byte_count = (node.total_size - node.header_size as u32) / 4;

        for i in 0..attr_byte_count as usize {
            let res_id: u32 = reader.read_u32::<LittleEndian>().unwrap();
            println!("Read resource id {} 0x{:08x}", self.strings[i], res_id);
            self.resource_map.push(res_id);
        }
    }

    fn read_string_pool(&mut self, reader: &mut Cursor<&Vec<u8>>, node: res_chunk_header) {


        let string_count: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let style_count: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let flags: u32 = reader.read_u32::<LittleEndian>().unwrap();
        let string_start: u32 = node.position + reader.read_u32::<LittleEndian>().unwrap();
        let styles_start: u32 = node.position + reader.read_u32::<LittleEndian>().unwrap();

        // TODO Debug
        let pos = reader.position();
        println!("Stringpool 0x{:04x}: strings {}, styles {}, flags: 0x{:04x}, string_start \
                  0x{:04x}, styles_start 0x{:04x}",
                 pos,
                 string_count,
                 style_count,
                 flags,
                 string_start,
                 styles_start);

        let UTF8_FLAG = 1 << 8;
        let isUTF8 = (flags & UTF8_FLAG) != 0;
        if isUTF8 {
            panic!("We are dealing with UTF-8. Not implemented yet");
        }

        if string_count != 0 {
            for i in 0..string_count {
                let string_pos: u32 = reader.read_u32::<LittleEndian>().unwrap();
                let seek_pos = reader.position();

                reader.seek(SeekFrom::Start((string_pos + string_start + 2) as u64));

                let mut buffer = Vec::new();
                let mut byte: u16 = 0xFFFF;
                loop {
                    match reader.read_u16::<LittleEndian>() {
                        Err(why) => panic!("Could not read: {}", why),
                        Ok(data) if data == 0x0000 => break,
                        Ok(data) => buffer.push(data),
                    }
                }

                let string = String::from_utf16_lossy(buffer.as_slice());
                // Todo debug
                println!("String {}:  0x{:04x} {} bytes: {}",
                         i,
                         string_pos,
                         string.len(),
                         string);

                self.strings.push(string);

                reader.seek(SeekFrom::Start(seek_pos as u64));
            }
        }

        if style_count != 0 {
            panic!("Need to parse styles");
        }

        let nextNode: u64 = (node.position + node.total_size) as u64;
        reader.seek(SeekFrom::Start(nextNode));

    }

    fn to_string(&self) -> String {
        if self.axml.len() > 1 {
            panic!("Multiple Namespaces not yet supported");
        }

        return self.axml[0].string(&self.strings, 0);
    }
}
impl AXMLNode {
    fn string(&self, string_pool: &Vec<String>, depth: u16) -> String {
        {
            let content = self.content.as_ref().unwrap();
            match content {
                &AXMLNode_content::AXMLNode_namespace { ref lineNumber,
                                                        ref comment,
                                                        ref prefix,
                                                        ref uri } => {
                    for child in 0..self.children.len() {
                        self.children[child].string(string_pool, depth);
                    }
                }
                &AXMLNode_content::AXMLNode_element { lineNumber,
                                                      comment,
                                                      ns,
                                                      ref name,
                                                      attribute_start,
                                                      attribute_size,
                                                      attribute_count,
                                                      id_index,
                                                      class_index,
                                                      style_index,
                                                      ref attributes } => {
                    let index = *name as usize;
                    for i in 0..depth {
                        print!("  ");
                    }
                    print!("<{} ", string_pool[index]);

                    for attr in 0..attributes.len() {
                        let ns = attributes[attr].ns as usize;
                        if ns <= string_pool.len() {
                            print!("{}:", string_pool[ns - 1]);
                        }

                        let name = attributes[attr].name as usize;
                        print!("{}", string_pool[name]);

                        let data = attributes[attr].data as usize;
                        if data <= string_pool.len() {
                            print!("=\"{}\" ", string_pool[data]);
                        } else {
                            print!(" ");
                        }
                    }
                    println!(">");

                    for child in 0..self.children.len() {
                        self.children[child].string(string_pool, depth + 1);
                    }

                    for i in 0..depth {
                        print!("  ");
                    }
                    println!("</{}>", string_pool[index]);
                }
                _ => {
                    panic!("WHAT IS LOVE?");
                }
            };

        }


        return "".to_string();
    }
}


pub fn decode(xml_data: &Vec<u8>) -> String {
    println!("axml::decode {} bytes of data", xml_data.len());

    let mut reader = Cursor::new(xml_data);

    let root_node = res_chunk_root::new(&mut reader);

    return root_node.to_string();
}
