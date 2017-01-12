extern crate zip;
extern crate xml;

#[macro_use]
extern crate nom;

mod dex;

use std::io::Read;
use std::io::{Write, BufWriter};
use std::error::Error;
use std::path::Path;
use std::fs::File;
use std::fs;

use zip::ZipArchive;
use zip::read::ZipFile;

fn main() {
    let path = Path::new("E:\\andromeda\\HelloWorld.apk");
    let file: File = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", path.display(), why.description()),
        Ok(file) => {
            println!("Reading APK {}", path.display());
            file
        }
    };

    // Unzip APK
    let mut zip = ZipArchive::new(&file).unwrap();

    // Read Manifest
    {
        let manifest_name = "AndroidManifest.xml";

        let mut manifest: ZipFile = zip.by_name(manifest_name).unwrap();

        let mut data: Vec<u8> = Vec::new();
        manifest.read_to_end(&mut data).expect("Unable to read data");
        // println!("AndroidManifest is {} ", axml::decode(&data));

    }
    // Read dex
    {
        let classes_name = "classes.dex";

        let mut dex_file: ZipFile = zip.by_name(classes_name).unwrap();

        let mut data: Vec<u8> = Vec::new();
        dex_file.read_to_end(&mut data).expect("Unable to read data");

        dex::parse(data);
    }
    println!("Unzippping");
    for i in 0..zip.len() {

        let mut zip_file: ZipFile = zip.by_index(i).unwrap();

        let mut data: Vec<u8> = Vec::new();
        zip_file.read_to_end(&mut data).expect("Unable to read data");
        let zip_file = zip_file;

        let path = Path::new("out");
        let file_name = zip_file.name();

        // println!("Unzippping: {}", file_name);
        let path = path.join(file_name);

        fs::create_dir_all(path.parent().unwrap());
        let dest = File::create(path).unwrap();
        let mut dest = BufWriter::new(dest);

        dest.write_all(&data).unwrap();
    }
}
