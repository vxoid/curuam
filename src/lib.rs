use std::time::{
    Duration,
    SystemTimeError,
};

pub const ICMP_HEADER_SIZE: usize = std::mem::size_of::<IcmpHeader>();
pub const ARP_HEADER_SIZE: usize = std::mem::size_of::<ArpHeader>();
pub const ETH_HEADER_SIZE: usize = std::mem::size_of::<EthHeader>();
pub const IP_HEADER_SIZE: usize = std::mem::size_of::<Ipv4Header>();
pub const IPV6_LEN: usize = 16;
pub const IPV4_LEN: usize = 4;
pub const MAC_LEN: usize = 6;

/// trait for conveting one type into other similar to the From trait
/// # Examples
/// ```
/// use curuam::*;
///
/// enum Bit {
///     One,
///     Zero
/// }
///
/// impl Handle<bool> for Bit {
///     fn from(value: bool) -> Self {
///         match value {
///             true => Self::One,
///             false => Self::Zero
///         }
///     }
///     fn to(&self) -> bool {
///         match *self {
///             Self::One => true,
///             Self::Zero => false,
///         }
///     }
/// }
///
/// let boolean: bool = Bit::Zero.to();
///
/// assert_eq!(boolean, false)
/// ```
pub trait Handle<T> {
    fn from(value: T) -> Self;
    fn to(&self) -> T;
}

/// struct for representing prime numbers
pub struct Prime;

/// struct for representing ipv4 addresses
///
/// # Example
/// ```
/// use curuam::*;
///
/// let ip_addr: Ipv4 = Handle::from([192, 168, 1, 1]);
///
/// let ip_octets: [u8; IPV4_LEN] = ip_addr.to(); // Basicly IPV4_LEN is count of octets of ipv4 (4)
///
/// assert_eq!(ip_octets, [192, 168, 1, 1])
/// ```
pub struct Ipv4 {
    octets: [u8; IPV4_LEN],
}

/// struct for representing ipv6 addresses
///
/// # Example
/// ```
/// use curuam::*;
///
/// let ip_addr: Ipv6 = Handle::from([0; IPV6_LEN]); // Bassicly IPV6_LEN is count of octets of ipv6 (16)
///
/// let ip_octets: [u8; IPV6_LEN] = ip_addr.to();
///
/// assert_eq!(ip_octets, [0; IPV6_LEN])
/// ```
pub struct Ipv6 {
    octets: [u8; IPV6_LEN],
}

/// struct for representing mac addresses
///
/// # Example
/// ```
/// use curuam::*;
///
/// let mac_addr: Mac = Handle::from([0xff; MAC_LEN]);
///
/// let mac_octets: [u8; MAC_LEN] = mac_addr.to();
///
/// assert_eq!(mac_octets, [0xff; MAC_LEN])
/// ```
pub struct Mac {
    mac_addr: [u8; MAC_LEN],
}

/// wrapper around type's pointer simple to box or arc smart pointer
///
/// # Example
/// ```
/// use curuam::*;
///
/// let a = 1;
///
/// let a_wrapper = Wrapper::new(&a);
///
/// assert_eq!(*a_wrapper.reference(), a)
/// ```
pub struct Wrapper<T: ?Sized> {
    pointer: *const T,
}

/// arp header
#[repr(C)]
pub struct ArpHeader {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub opcode: u16,
    pub sender_mac: [u8; MAC_LEN],
    pub sender_ip: [u8; IPV4_LEN],
    pub target_mac: [u8; MAC_LEN],
    pub target_ip: [u8; IPV4_LEN],
}

/// icmp header
#[repr(C)]
pub struct IcmpHeader {
    pub type_: u8,
    pub code: u8,
    pub check: u16,
    pub id: u16,
    pub sq: u16,
}

/// eth header
#[repr(C)]
pub struct EthHeader {
    pub dest: [u8; MAC_LEN],
    pub source: [u8; MAC_LEN],
    pub proto: u16,
}

/// ipv4 header
#[repr(C)]
pub struct Ipv4Header {
    pub verihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: [u8; IPV4_LEN],
    pub daddr: [u8; IPV4_LEN],
}

/// ipv6 header 
#[repr(C)]
pub struct Ipv6Header {
    pub verlab: u32,
    pub payload: u16,
    pub next: u8,
    pub hop: u8,
    pub src: [u8; IPV6_LEN],
    pub dst: [u8; IPV6_LEN]
}

impl Prime {
    pub fn is_prime(u: u128) -> bool {
        if u <= 1 {
            return false
        }

        for i in 2..u {
            if u % i == 0 {
                return false;
            }
        }

        true
    }
    pub fn range(start: u128, end: u128) -> Vec<u128> {
        let mut primes: Vec<u128> = Vec::new();
        
        for u in start..end {
            if Self::is_prime(u) {
                primes.push(u)
            } 
        }

        primes
    }
}

impl<T: ?Sized> Wrapper<T> {
    pub fn new(pointer: *const T) -> Self {
        Self { pointer }
    }
    pub fn reference(&self) -> &T {
        unsafe { &*self.pointer }
    }
    pub fn mut_reference(&self) -> &mut T {
        unsafe { &mut *(self.pointer as *mut T) }
    }
}

unsafe impl<T: ?Sized> Send for Wrapper<T> {}

impl Clone for Mac {
    fn clone(&self) -> Self {
        Self {
            mac_addr: self.mac_addr.clone(),
        }
    }
}

impl Handle<[u8; MAC_LEN]> for Mac {
    fn from(mac_addr: [u8; MAC_LEN]) -> Self {
        Self { mac_addr }
    }
    fn to(&self) -> [u8; MAC_LEN] {
        self.mac_addr.clone()
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.mac_addr[0],
            self.mac_addr[1],
            self.mac_addr[2],
            self.mac_addr[3],
            self.mac_addr[4],
            self.mac_addr[5]
        )
    }
}

impl Clone for Ipv4 {
    fn clone(&self) -> Self {
        Self {
            octets: self.octets.clone(),
        }
    }
}

impl Handle<[u8; IPV4_LEN]> for Ipv4 {
    fn from(ip_addr: [u8; IPV4_LEN]) -> Self {
        Self { octets: ip_addr }
    }
    fn to(&self) -> [u8; IPV4_LEN] {
        self.octets.clone()
    }
}

impl Clone for Ipv6 {
    fn clone(&self) -> Self {
        Self { octets: self.octets.clone() }
    }
}

impl Handle<[u8; IPV6_LEN]> for Ipv6 {
    fn from(octets: [u8; IPV6_LEN]) -> Self {
        Self { octets }
    }
    fn to(&self) -> [u8; IPV6_LEN] {
        self.octets.clone()
    }
}

impl std::fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3],
        )
    }
}

impl Handle<u32> for Ipv4 {
    fn from(value: u32) -> Self {
        let o1: u8 = (value & 0xff) as u8;
        let o2: u8 = ((value >> 8) & 0xff) as u8;
        let o3: u8 = ((value >> 16) & 0xff) as u8;
        let o4: u8 = ((value >> 24) & 0xff) as u8;

        Handle::from([o4, o3, o2, o1])
    }
    fn to(&self) -> u32 {
        ((self.octets[0] as u32) << 24)
            + ((self.octets[1] as u32) << 16)
            + ((self.octets[2] as u32) << 8)
            + ((self.octets[3] as u32) << 0)
    }
}

/// function for building to the exponent
///
/// # Example
/// ```
/// use curuam::*;
///
/// let a = 3;
/// let b = power(a as f64, 2); // 1*3*3
///
/// assert_eq!(b, 9f64)
/// ```
pub fn power(f: f64, power: u16) -> f64 {
    power_with_start(1f64, f, power)
}

fn power_with_start(start: f64, f: f64, power: u16) -> f64 {
    let mut out: f64 = start;

    for _ in 0..power {
        out *= f
    }

    out
}

/// c memcpy clone
///
/// # Example
///
/// ```
/// use curuam::*;
///
/// let a: [i128; 4] = [1210, 3271231, 478654, 239]; // Just random numbers
/// let mut b: [i128; 4] = [0; 4];
/// let mut c: [i128; 4] = [0; 4];
///
/// memcpy(&mut b, &a, std::mem::size_of::<[i128; 4]>());
/// memcpy(c.as_mut_ptr(), a.as_ptr(), std::mem::size_of::<[i128; 4]>());
///
/// assert_eq!(a, b);
/// assert_eq!(a, c);
/// assert_eq!(b, c)
/// ```
pub fn memcpy<TD, TS>(dest: *mut TD, src: *const TS, size: usize) -> *mut TD {
    if dest as usize == 0 {
        return 0 as *mut TD;
    }

    let byte_dest: *mut u8 = dest as *mut u8;
    let byte_src: *const u8 = src as *const u8;

    unsafe {
        for i in 0..size {
            *((byte_dest as usize + i) as *mut u8) = *((byte_src as usize + i) as *const u8)
        }
    }

    dest
}

/// creates string from bytes
///
/// # Example
/// ```
/// use curuam::*;
///
/// let bytes = b"Hello, world";
///
/// assert_eq!(str_from_bytes(bytes).as_bytes(), bytes)
/// ```
pub fn str_from_bytes(bytes: &[u8]) -> String {
    let mut string: String = String::new();

    for byte in bytes {
        string.push(byte.clone() as char)
    }

    string
}

/// creates string from char pointer
///
/// # Example
/// ```
/// use curuam::*;
/// use std::ffi::CString;
///
/// let string = "Hello, world";
/// let cstring = CString::new(string).expect("cstring init error");
///
/// assert_eq!(&str_from_cstr(cstring.as_ptr())[..], string)
/// ```
pub fn str_from_cstr(cstr: *const i8) -> String {
    let mut string: String = String::new();

    let mut i: usize = 0;
    loop {
        let byte: i8 = unsafe { *((cstr as usize + i) as *const i8) };
        if byte == 0 {
            break;
        }

        string.push(byte as u8 as char);

        i += 1
    }

    string
}

pub fn str_from_cutf16(str: *const u16) -> String {

    let mut message: String = String::new();
    let mut i: usize = 0;

    loop {
        let value: u16 = unsafe {
            *((str as usize + i) as *const u16)
        };
        if value == 0 {
            break;
        }

        message.push(value as u8 as char);
        i += 1;
    }

    message
}

pub type RandomNumber = u128;
pub fn random_with_seed(seed: RandomNumber) -> RandomNumber {
    const SEED_OFFSET: u8 = 8;

    const MULTIPLIER: RandomNumber = 9;
    const ADDER: RandomNumber = 5;
    let mut seed: RandomNumber = seed;
    let mut result: RandomNumber = 0;
    let mut i: usize = 0;
    
    loop {
        if (i*SEED_OFFSET as usize) >= RandomNumber::BITS as usize {
            break
        }

        seed = ((seed*MULTIPLIER)+ADDER)%power(2f64, SEED_OFFSET as u16) as RandomNumber;
        result += seed << 8*i;

        i += 1;
    }

    !result
}

pub fn random_in_range(min: RandomNumber, max: RandomNumber) -> Result<RandomNumber, SystemTimeError> {
    let unix_epoch: Duration = std::time::UNIX_EPOCH.elapsed()?;
    Ok(random_with_seed(unix_epoch.as_nanos() as RandomNumber)%(max-min)+min)
}

pub fn checksum(header: *const u8, len: usize) -> u16 {
    let mut sum: i32 = 0;
    let mut left: usize = len;
    let words: *const u16 = header as *const u16; 

    let mut i: usize = 0;
    while left > 1 {
        sum += unsafe {
            *((words as usize + i) as *const u16)
        } as i32;

        left -= 2;
        i += 2
    }

    if left == 1 {            
        sum += unsafe {
            *((words as usize + i - 1) as *const u8)
        } as i32;
    }

    sum = (sum >> 16) + (sum & 0xffff); 
    sum += sum >> 16;

    (!sum) as u16
}