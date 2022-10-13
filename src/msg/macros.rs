/// Macro for creating enums that have number values that
/// can be compared and encoded using Codec
macro_rules! codec_enum {
    (
        ($ty:ty) enum $name:ident {
            $(
                $field:ident = $value:expr
            ),* $(,)?
        }
    ) => {
        /// Generated enum with unknown field added for
        /// handling unknown types
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub enum $name {
            $(
               $field
            ),*,
            Unknown($ty)
        }

        impl $name {

            /// Function for converting this enum field into
            /// its type value
            pub fn value(&self) -> $ty {
                match self {
                    $(Self::$field => $value,)*
                    Self::Unknown(value) => *value
                }
            }

            /// Function for converting a type value into a
            /// field on this enum
            pub fn from_value(value: $ty) -> Self {
                match value {
                    $($value => Self::$field,)*
                    value => Self::Unknown(value)
                }
            }
        }

        impl $crate::msg::Codec for $name {
            fn encode(&self, output: &mut Vec<u8>) {
                self.value().encode(output);
            }

            fn decode(input: &mut $crate::msg::Reader) -> Option<Self> {
                Some(Self::from_value(<$ty>::decode(input)?))
            }
        }

    };
}