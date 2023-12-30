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
/// decode and encode functions
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

impl u24 {
    pub const MAX: usize = 0xff_ffff;
}

#[cfg(target_pointer_width = "32")]
impl From<usize> for u24 {
    fn from(value: usize) -> Self {
        // Sanity bounds checking
        debug_assert!(value <= Self::MAX);

        // u24 uses the last 3 bytes of the 32bit integer
        let bytes = value.to_be_bytes();
        Self([bytes[1], bytes[2], bytes[3]])
    }
}

#[cfg(target_pointer_width = "64")]
impl From<usize> for u24 {
    fn from(value: usize) -> Self {
        // Sanity bounds checking
        debug_assert!(value <= Self::MAX);

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

/// Trait implemented by types that can be used as the length
/// of a vec of bytes (For encoding vecs)
pub trait VecLength: Codec + Into<usize> {
    /// Size in bytes of the encoded value
    const SIZE: usize;

    /// Creates the length value from a usize
    fn from_usize(value: usize) -> Self;
}

impl VecLength for u8 {
    const SIZE: usize = 1;

    #[inline]
    fn from_usize(value: usize) -> Self {
        // Sanity checking length is within type bounds
        debug_assert!(value < Self::MAX as usize);

        value as u8
    }
}

impl VecLength for u16 {
    const SIZE: usize = 2;

    #[inline]
    fn from_usize(value: usize) -> Self {
        // Sanity checking length is within type bounds
        debug_assert!(value < Self::MAX as usize);

        value as u16
    }
}

impl VecLength for u24 {
    const SIZE: usize = 3;

    #[inline]
    fn from_usize(value: usize) -> Self {
        // Sanity checking length is within type bounds
        debug_assert!(value < Self::MAX);

        u24::from(value)
    }
}

/// Attempts to decode a collection of `Value` where the length in bytes
/// is represented by type `Length`.
pub fn decode_vec<Length, Value>(input: &mut Reader) -> Option<Vec<Value>>
where
    Length: VecLength,
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

pub fn encode_vec<Length, Value>(output: &mut Vec<u8>, values: Vec<Value>)
where
    Length: VecLength,
    Value: Codec,
{
    // Length of the output before writing
    let start_length: usize = output.len();

    // Encode initial zero length
    Length::from_usize(0usize).encode(output);

    // Encode the vec values
    for value in values {
        value.encode(output);
    }

    // Length of the output after writing
    let end_length: usize = output.len();

    // Get the length of the encoded content (Total - Start - Length Size)
    let content_length: usize = end_length - start_length - Length::SIZE;

    // Safety: Only ever sets the length to memory thats within
    // capacity and is already initialized
    unsafe {
        // Move writing to the initial position
        output.set_len(start_length);
        // Write the actual length value
        Length::from_usize(content_length).encode(output);
        // Restore writer length position
        output.set_len(end_length);
    }
}
