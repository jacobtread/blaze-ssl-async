use num_enum::FromPrimitive;

/// Structure that allows reading through a slice of bytes
/// using a cursor state for positioning.
pub struct Reader<'a> {
    /// The buffer to read from
    buf: &'a [u8],
    /// The cursor position on the buffer
    cursor: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new reader for the provided buffer. The
    /// initial cursor position begins at zero.
    ///
    /// # Arguments
    /// * buf - The buffer to wrap
    pub fn new(buf: &[u8]) -> Reader {
        Reader { buf, cursor: 0 }
    }

    /// Takes a slice of the underlying slice from the cursor
    /// position to the end of the slice. Moves the cursor to
    /// the ender of the slice.
    pub fn remaining(&mut self) -> &[u8] {
        let ret = &self.buf[self.cursor..];
        self.cursor = self.buf.len();
        ret
    }

    /// Attempts to take a single byte from the underlying
    /// slice and move the cursor. Return None if there is
    /// no bytes past the cursor
    pub fn take_byte(&mut self) -> Option<u8> {
        if self.available() < 1 {
            return None;
        }
        let value = self.buf[self.cursor];
        self.cursor += 1;
        Some(value)
    }

    /// Takes a fixed length of bytes copying rather than
    /// providing a reference, will return [None] if there
    /// is not enough bytes
    pub fn take_fixed<const LENGTH: usize>(&mut self) -> Option<[u8; LENGTH]> {
        if self.available() < LENGTH {
            return None;
        }

        let last_cursor = self.cursor;
        self.cursor += LENGTH;

        let mut slice = [0u8; LENGTH];
        slice.copy_from_slice(&self.buf[last_cursor..self.cursor]);

        Some(slice)
    }

    /// Attempt to take the provided `length` of bytes. If there
    /// is not enough bytes in the buffer after the current cursor
    /// position None will be returned instead.
    ///
    /// # Arguments
    /// * length - The length of the slice to take
    pub fn take(&mut self, length: usize) -> Option<&[u8]> {
        if self.available() < length {
            return None;
        }
        let last_cursor = self.cursor;
        self.cursor += length;
        Some(&self.buf[last_cursor..self.cursor])
    }

    /// Return the number of available length that can be
    /// visited using the cursor.
    pub fn available(&self) -> usize {
        self.buf.len() - self.cursor
    }

    /// Returns whether there is more bytes to read from the
    /// slice (The cursor hasn't reached the buf length yet)
    pub fn has_more(&self) -> bool {
        self.cursor < self.buf.len()
    }

    /// Return the cursor position (The position in the buffer
    /// that the next read will take place from)
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Attempts to create a new reader from a slice of the
    /// provided length. Will return None if the required
    /// length was not available
    ///
    /// `length` The length of the slice to take
    pub fn slice(&mut self, length: usize) -> Option<Reader> {
        self.take(length).map(Reader::new)
    }
}

/// Trait implementing a structure for reading and writing
/// the implementation to a Reader or writing to a Vec of
/// bytes.
pub trait Codec: Sized {
    /// Trait function for encoding the implementation
    /// and appending it to the output byte vec
    fn encode(self, output: &mut Vec<u8>);

    /// Trait function for decoding the implementation
    /// from the reader. if the decoding fails then
    /// None should be returned
    fn decode(input: &mut Reader) -> Option<Self>;
}

/// Trait implemented by enums that can use their [num_enum::FromPrimitive] and
/// [num_enum::IntoPrimitive] implementations to automatically create [Codec]
/// deoce and encode functions
pub trait EnumCodec: FromPrimitive + Into<Self::Primitive>
where
    Self: Copy,
    Self::Primitive: Codec,
{
}

impl<E, C> Codec for E
where
    E: EnumCodec<Primitive = C>,
    C: Codec,
{
    fn encode(self, output: &mut Vec<u8>) {
        let primitive: C = self.into();
        primitive.encode(output);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        C::decode(input).map(Self::from_primitive)
    }
}

/// Implements encoding and decoding of u8 values
impl Codec for u8 {
    fn encode(self, output: &mut Vec<u8>) {
        output.push(self);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take_byte()
    }
}

impl Codec for u16 {
    fn encode(self, output: &mut Vec<u8>) {
        let out_slice: [u8; 2] = self.to_be_bytes();
        output.extend_from_slice(&out_slice);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take_fixed::<2>().map(u16::from_be_bytes)
    }
}

/// SSL 24bit integer value, used for length fields
#[allow(non_camel_case_types)]
pub struct u24(pub(crate) [u8; 3]);

#[cfg(target_pointer_width = "32")]
impl From<usize> for u24 {
    fn from(value: usize) -> Self {
        // u24 uses the last 3 bytes of the 32bit integer
        let bytes = value.to_be_bytes();
        Self([bytes[1], bytes[2], bytes[3]])
    }
}

#[cfg(target_pointer_width = "64")]
impl From<usize> for u24 {
    fn from(value: usize) -> Self {
        // u24 uses the last 3 bytes of the 64bit integer
        let bytes = value.to_be_bytes();
        Self([bytes[5], bytes[6], bytes[7]])
    }
}

#[cfg(target_pointer_width = "32")]
impl From<u24> for usize {
    fn from(value: u24) -> Self {
        let bytes = value.0;
        usize::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
    }
}

#[cfg(target_pointer_width = "64")]
impl From<u24> for usize {
    fn from(value: u24) -> Self {
        let bytes = value.0;
        usize::from_be_bytes([0, 0, 0, 0, 0, bytes[0], bytes[1], bytes[2]])
    }
}

impl Codec for u24 {
    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0)
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take_fixed::<3>().map(u24)
    }
}

impl Codec for u32 {
    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.to_be_bytes())
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take_fixed::<4>().map(u32::from_be_bytes)
    }
}

/// Attempts to decode a collection of `C` where the length in bytes
/// is represented by type `L`.
pub fn decode_vec<Length, Value>(input: &mut Reader) -> Option<Vec<Value>>
where
    Length: Codec + Into<usize>,
    Value: Codec,
{
    let length: usize = Length::decode(input)?.into();
    let mut input = input.slice(length)?;
    let mut values = Vec::new();
    while input.has_more() {
        values.push(Value::decode(&mut input)?);
    }
    Some(values)
}

pub fn encode_vec_u8<T: Codec>(bytes: &mut Vec<u8>, items: Vec<T>) {
    let len_offset = bytes.len();
    bytes.push(0);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 1;
    debug_assert!(len <= 0xff);
    bytes[len_offset] = len as u8;
}

pub fn encode_vec_u16<T: Codec>(bytes: &mut Vec<u8>, items: Vec<T>) {
    let len_offset = bytes.len();
    bytes.extend([0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 2;
    debug_assert!(len <= 0xffff);
    let out: &mut [u8; 2] = (&mut bytes[len_offset..len_offset + 2]).try_into().unwrap();
    *out = u16::to_be_bytes(len as u16);
}

pub fn encode_vec_u24<T: Codec>(bytes: &mut Vec<u8>, items: Vec<T>) {
    let len_offset = bytes.len();
    bytes.extend([0, 0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 3;
    debug_assert!(len <= 0xff_ffff);
    let len_bytes = u32::to_be_bytes(len as u32);
    let out: &mut [u8; 3] = (&mut bytes[len_offset..len_offset + 3]).try_into().unwrap();
    out.copy_from_slice(&len_bytes[1..]);
}
