use crate::metadata::error::MetadataError;

#[derive(Debug, Clone, Copy, Default)]
pub struct Section {
    pub offset: i32,
    pub size: i32,
}

impl Section {
    pub fn count_of(&self, stride: usize) -> Result<usize, MetadataError> {
        if self.size < 0 || self.offset < 0 {
            return Err(MetadataError::InvalidSection {
                offset: self.offset,
                size: self.size,
            });
        }
        if stride == 0 {
            return Ok(0);
        }
        if !(self.size as usize).is_multiple_of(stride) {
            return Err(MetadataError::BadStride {
                size: self.size as usize,
                stride,
            });
        }
        Ok(self.size as usize / stride)
    }

    pub fn end(&self) -> i64 {
        self.offset as i64 + self.size as i64
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MetadataHeader {
    pub sanity: u32,
    pub version: i32,
    pub string_literal: Section,
    pub string_literal_data: Section,
    pub string: Section,
    pub events: Section,
    pub properties: Section,
    pub methods: Section,
    pub parameter_default_values: Section,
    pub field_default_values: Section,
    pub field_and_parameter_default_value_data: Section,
    pub field_marshaled_sizes: Section,
    pub parameters: Section,
    pub fields: Section,
    pub generic_parameters: Section,
    pub generic_parameter_constraints: Section,
    pub generic_containers: Section,
    pub nested_types: Section,
    pub interfaces: Section,
    pub vtable_methods: Section,
    pub interface_offsets: Section,
    pub type_definitions: Section,
    pub images: Section,
    pub assemblies: Section,
    pub field_refs: Section,
    pub referenced_assemblies: Section,
    pub attributes_info: Section,
    pub attributes_types: Section,
    pub attribute_data: Section,
    pub attribute_data_range: Section,
    pub unresolved_indirect_call_parameter_types: Section,
    pub unresolved_indirect_call_parameter_ranges: Section,
    pub windows_runtime_type_names: Section,
    pub windows_runtime_strings: Section,
    pub exported_type_definitions: Section,
}

pub const METADATA_MAGIC: u32 = 0xFAB1_1BAF;
pub const METADATA_VERSION: i32 = 29;
pub const HEADER_SIZE: usize = 0x110;

struct Cursor<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, off: 0 }
    }

    fn u32(&mut self) -> Result<u32, MetadataError> {
        if self.off + 4 > self.data.len() {
            return Err(MetadataError::Truncated { at: self.off });
        }
        let v = u32::from_le_bytes(self.data[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        Ok(v)
    }

    fn i32(&mut self) -> Result<i32, MetadataError> {
        Ok(self.u32()? as i32)
    }

    fn section(&mut self) -> Result<Section, MetadataError> {
        Ok(Section {
            offset: self.i32()?,
            size: self.i32()?,
        })
    }
}

impl MetadataHeader {
    pub fn parse(data: &[u8]) -> Result<Self, MetadataError> {
        if data.len() < HEADER_SIZE {
            return Err(MetadataError::TooSmall {
                need: HEADER_SIZE,
                got: data.len(),
            });
        }

        let mut c = Cursor::new(data);
        let sanity = c.u32()?;
        let version = c.i32()?;

        if sanity != METADATA_MAGIC {
            return Err(MetadataError::BadMagic { got: sanity });
        }
        if version != METADATA_VERSION {
            return Err(MetadataError::UnsupportedVersion { version });
        }

        let header = Self {
            sanity,
            version,
            string_literal: c.section()?,
            string_literal_data: c.section()?,
            string: c.section()?,
            events: c.section()?,
            properties: c.section()?,
            methods: c.section()?,
            parameter_default_values: c.section()?,
            field_default_values: c.section()?,
            field_and_parameter_default_value_data: c.section()?,
            field_marshaled_sizes: c.section()?,
            parameters: c.section()?,
            fields: c.section()?,
            generic_parameters: c.section()?,
            generic_parameter_constraints: c.section()?,
            generic_containers: c.section()?,
            nested_types: c.section()?,
            interfaces: c.section()?,
            vtable_methods: c.section()?,
            interface_offsets: c.section()?,
            type_definitions: c.section()?,
            images: c.section()?,
            assemblies: c.section()?,
            field_refs: c.section()?,
            referenced_assemblies: c.section()?,
            attributes_info: c.section()?,
            attributes_types: c.section()?,
            attribute_data: c.section()?,
            attribute_data_range: c.section()?,
            unresolved_indirect_call_parameter_types: c.section()?,
            unresolved_indirect_call_parameter_ranges: c.section()?,
            windows_runtime_type_names: c.section()?,
            windows_runtime_strings: c.section()?,
            exported_type_definitions: c.section()?,
        };

        debug_assert_eq!(c.off, HEADER_SIZE);

        if header.string_literal.offset as usize != HEADER_SIZE {
            return Err(MetadataError::UnexpectedHeaderSize {
                string_literal_offset: header.string_literal.offset,
            });
        }

        Ok(header)
    }
}
