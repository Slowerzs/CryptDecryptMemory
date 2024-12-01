use libaes::Cipher;
use sha1::{Digest, Sha1};
use std::{
    ffi::c_void,
    fs::{self, File},
    io::Cursor,
    ptr::{null, null_mut},
};

use kdmp_parser::{Gva, Gxa, KernelDumpParser};
use symbolic::debuginfo::{pdb, pdb::pdb::FallibleIterator, pe::PeObject};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, NTSTATUS},
        Security::Cryptography::{CryptProtectMemory, CRYPTPROTECTMEMORY_SAME_PROCESS},
        Storage::FileSystem::{
            CreateFileA, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
        },
    },
};

// Taken from https://docs.rs/symcrypt-sys/latest/symcrypt_sys/type.SYMCRYPT_SHA1_STATE.html
#[allow(non_camel_case_types, non_snake_case)]
struct SYMCRYPT_SHA1_STATE {
    pub _padding: [u8; 0x20],
    pub buffer: [u8; 0x18],
}

fn main() {
    let plaintext_data_original = [0u8; 0x20];
    println!("Original data : {:X?}", plaintext_data_original);
    let mut plaintext_data = plaintext_data_original.clone();

    unsafe {
        CryptProtectMemory(
            plaintext_data.as_mut_ptr() as *mut c_void,
            plaintext_data.len() as u32,
            CRYPTPROTECTMEMORY_SAME_PROCESS,
        )
        .expect("Failed :(")
    };

    println!("Encrypted: {:X?}", plaintext_data);

    create_dump_file(r"C:\Windows\Temp\livedump.DMP".to_string())
        .expect("[-] Failed creating livedump.");

    let dump_file = File::open(r"C:\Windows\Temp\livedump.DMP")
        .expect("[-] Failed opening livedump.");

    let dump_parser =
        KernelDumpParser::with_reader(dump_file).expect("[-] Failed parsing livedump.");

    let active_process_head = dump_parser.headers().ps_active_process_head;

    println!("[+] Found PsActiveProcessListHead: {active_process_head:#X}");

    let cng_data =
        fs::read(r"C:\Windows\System32\drivers\cng.sys").expect("[-] Failed reading cng.sys");

    let cng_object = PeObject::parse(&cng_data).expect("[-] Failed parsing cng.sys");
    let pdb_id = cng_object.debug_id().to_string().replace("-", "");
    let pdb_url = format!("https://msdl.microsoft.com/download/symbols/cng.pdb/{pdb_id}/cng.pdb");
    println!("[+] Downloading cng.sys PDB from {:?}", pdb_url);

    let cng_pdb_data = reqwest::blocking::get(pdb_url)
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();

    let mut pdb_parser =
        pdb::pdb::PDB::open(Cursor::new(cng_pdb_data)).expect("[-] Failed parsing PDB data.");

    let mut random_salt_offset = 0;
    let mut g_sha_hash_offset = 0;
    let address_map = pdb_parser
        .address_map()
        .expect("[-] Failed building address map");

    let symbol_table = pdb_parser
        .global_symbols()
        .expect("[-] Failed parsing PDB.");
    let mut symbols = symbol_table.iter();
    while let Some(sym) = symbols.next().unwrap() {
        match sym.parse() {
            Ok(pdb::pdb::SymbolData::Public(data)) => {
                if data.name.to_string().eq("?RandomSalt@@3PAEA") {
                    random_salt_offset = data
                        .offset
                        .to_rva(&address_map)
                        .expect("[-] Failed calculating RVA.")
                        .0;
                } else if data
                    .name
                    .to_string()
                    .eq("?g_ShaHash@@3U_SYMCRYPT_SHA1_STATE@@A")
                {
                    g_sha_hash_offset = data
                        .offset
                        .to_rva(&address_map)
                        .expect("[-] Failed calculating RVA.")
                        .0;
                }
            }
            _ => {}
        }
    }

    println!(
        "[+] Found cng.sys offsets
\tg_ShaHash offset {g_sha_hash_offset:#X}
\tRandomSalt offset {random_salt_offset:#X}"
    );

    let (cng_base, _) = dump_parser
        .kernel_modules()
        .filter(|(_range, name)| name.ends_with("cng.sys"))
        .next()
        .expect("[-] Failed finding cng.sys");

    let cng_base = cng_base.start.u64();
    println!("[+] cng.sys base address: {cng_base:#X}");

    let random_salt_value: [u8; 16];

    random_salt_value = dump_parser
        .virt_read_struct(Gva::new(cng_base + random_salt_offset as u64))
        .expect("[-] Failed reading RandomSalt value.");

    println!("\tRandomSalt: {:X?}", random_salt_value);

    let g_sha_hash_value: SYMCRYPT_SHA1_STATE;

    g_sha_hash_value = dump_parser
        .virt_read_struct(Gva::new(cng_base + g_sha_hash_offset as u64))
        .expect("[-] Failed reading g_ShaHash");
    println!("\tg_ShaHash: {:X?}", g_sha_hash_value.buffer);

    // NTOSKRNL.EXE
    let ntoskrnl_data =
        fs::read(r"C:\Windows\System32\ntoskrnl.exe").expect("[-] Failed reading ntoskrnl.exe");

    let ntoskrnl_object = PeObject::parse(&ntoskrnl_data).expect("[-] Failed parsing ntoskrnl.exe");
    let pdb_id = ntoskrnl_object.debug_id().to_string().replace("-", "");
    let pdb_url =
        format!("https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/{pdb_id}/ntkrnlmp.pdb");

    println!("[+] Downloading ntoskrnl.exe PDB from {:?}", pdb_url);

    let pdb_data = reqwest::blocking::get(pdb_url)
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();

    let mut pdb_parser =
        pdb::pdb::PDB::open(Cursor::new(pdb_data)).expect("[-] Failed parsing PDB data.");

    let type_infos = pdb_parser.type_information().unwrap();
    let mut type_finder = type_infos.finder();
    let mut iter = type_infos.iter();

    let mut active_process_link_offset = 0;
    let mut cookie_offset = 0;
    let mut creation_time_offset = 0;
    let mut pid_offset = 0;

    // Parse PDB to find offsets.

    while let Some(info) = iter.next().unwrap() {
        type_finder.update(&iter);
        match info.parse() {
            Ok(pdb::pdb::TypeData::Class(pdb::pdb::ClassType {
                name,
                properties: _,
                fields: Some(fields),
                ..
            })) => {
                if name.to_string().eq("_EPROCESS") {
                    match type_finder.find(fields).unwrap().parse().unwrap() {
                        pdb::pdb::TypeData::FieldList(list) => {
                            for field in list.fields {
                                if let pdb::pdb::TypeData::Member(member) = field {
                                    if member.name.to_string().eq("ActiveProcessLinks") {
                                        active_process_link_offset = member.offset;
                                    }
                                    if member.name.to_string().eq("Cookie") {
                                        cookie_offset = member.offset;
                                    }
                                    if member.name.to_string().eq("CreateTime") {
                                        creation_time_offset = member.offset;
                                    }
                                    if member.name.to_string().eq("UniqueProcessId") {
                                        pid_offset = member.offset;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    break;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }

    println!(
        "[+] Found EPROCESS offsets:
        UniqueProcessID offset: {pid_offset:#X}
        Cookie offset: {cookie_offset:#X}
        CreateTime offset: {creation_time_offset:#X}
        ActiveProcessLinks: {active_process_link_offset:#X}"
    );

    let target_pid = std::process::id();

    let mut eprocess_start: u64 = dump_parser
        .virt_read_struct(Gva::new(active_process_head))
        .expect("[-] Failed reading first EPROCESS.");

    eprocess_start -= active_process_link_offset;

    loop {
        let eprocess_pid: u64 = dump_parser
            .virt_read_struct(Gva::new(eprocess_start + pid_offset))
            .expect("[-] Failed reading PID of EPROCESS struct.");

        if eprocess_pid == target_pid as u64 {
            println!("[+] Found EPROCESS struct @ {eprocess_start:#X} for PID {target_pid}");
            break;
        }

        eprocess_start = dump_parser
            .virt_read_struct(Gva::new(eprocess_start + active_process_link_offset))
            .expect("Failed finding next EPROCESS.");
        eprocess_start -= active_process_link_offset;
    }

    let cookie_value: u64 = dump_parser
        .virt_read_struct(Gva::new(eprocess_start + cookie_offset))
        .expect("[-] Failed retrieving Cookie field.");
    let create_time: u64 = dump_parser
        .virt_read_struct(Gva::new(eprocess_start + creation_time_offset))
        .expect("[-] Failed retrieving CreateTime field.");

    println!("\tCookie: {cookie_value:#X}");
    println!("\tCreateTime: {create_time:#X}");
    let mut hasher = Sha1::new();
    hasher.update(g_sha_hash_value.buffer);

    let mut data = (cookie_value as u32).to_le_bytes().to_vec();

    data.extend(create_time.to_le_bytes());

    hasher.update(data);
    let hash = hasher.finalize();
    println!("[+] SHA1 hash : {:X?}", hash);

    let key: [u8; 16] = hash[..0x10].try_into().unwrap();
    //let mut aes_dec = Aes128::new(key.into(), &random_salt_value.into());
    let cipher = Cipher::new_128(&key);
    let decrypted = cipher.cbc_decrypt(&random_salt_value, &plaintext_data[..]);
    println!("[+] Decrypted AES data: {:X?}", decrypted);
    println!("Checking value is correctly decrypted...");
    assert_eq!(decrypted, plaintext_data_original);
    println!("[+] Success !");

}

#[derive(Debug)]
pub enum DumpError {
    CreateFileError,
    DebuggerNotEnabled,
}

#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
struct SYSDBG_LIVEDUMP_CONTROL {
    Version: u32,
    BugCheckCode: u32,
    BugCheckParam1: u64,
    BugCheckParam2: u64,
    BugCheckParam3: u64,
    BugCheckParam4: u64,
    FileHandle: HANDLE,
    CancelHandle: HANDLE,
    Flags: u32,
    Pages: u32,
}

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "C" {
    #[link_name = "NtSystemDebugControl"]
    fn NtSystemDebugControl(
        command: usize,
        input_buffer: *const SYSDBG_LIVEDUMP_CONTROL,
        input_buffer_length: usize,
        output_buffer: *const c_void,
        output_buffer_len: usize,
        return_length: *mut usize,
    ) -> NTSTATUS;
}

pub fn create_dump_file(path: String) -> Result<(), DumpError> {
    let file_handle = unsafe {
        CreateFileA(
            PCSTR(format!("{}\0", path).as_ptr()),
            0x10000000,
            FILE_SHARE_MODE(0),
            None,
            FILE_CREATION_DISPOSITION(2),
            FILE_FLAGS_AND_ATTRIBUTES(0x80),
            HANDLE::default(),
        )
        .map_err(|_| DumpError::CreateFileError)?
    };

    let dump_control = SYSDBG_LIVEDUMP_CONTROL {
        Version: 1,
        BugCheckCode: 0x161,
        BugCheckParam1: 0,
        BugCheckParam2: 0,
        BugCheckParam3: 0,
        BugCheckParam4: 0,
        FileHandle: file_handle,
        CancelHandle: HANDLE::default(),
        Flags: 0,
        Pages: 0,
    };

    let status = unsafe {
        NtSystemDebugControl(
            37,
            &dump_control,
            size_of::<SYSDBG_LIVEDUMP_CONTROL>(),
            null(),
            0,
            null_mut(),
        )
    };

    if status.is_err() {
        println!("NTSTATUS : {:#X}", status.0);
        return Err(DumpError::DebuggerNotEnabled);
    }

    unsafe { CloseHandle(file_handle).unwrap() };

    Ok(())
}
