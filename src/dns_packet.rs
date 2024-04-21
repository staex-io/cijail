use thiserror::Error;

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;
const HEADER_SIZE: usize = 12;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("too small")]
    TooSmall,
}

#[repr(u16)]
#[non_exhaustive]
pub(crate) enum Type {
    A = 1,
    Ptr = 12,
    Unknown = u16::MAX,
}

impl From<u16> for Type {
    fn from(other: u16) -> Self {
        match other {
            1 => Self::A,
            12 => Self::Ptr,
            _ => Self::Unknown,
        }
    }
}

#[cfg_attr(test, derive(Clone, PartialEq, Debug))]
pub struct DnsPacket {
    pub(crate) header: Header,
    pub(crate) questions: Vec<Question>,
    pub(crate) answers: Vec<Answer>,
    authorities: Vec<Answer>,
    additional: Vec<Answer>,
}

impl DnsPacket {
    #[cfg(test)]
    pub(crate) fn write(&mut self, bytes: &mut [u8]) -> Result<usize, DnsError> {
        self.header.num_questions = self.questions.len() as u16;
        self.header.num_answers = self.answers.len() as u16;
        self.header.num_authority = self.authorities.len() as u16;
        self.header.num_additional = self.additional.len() as u16;
        self.header.write(bytes);
        let mut offset = HEADER_SIZE;
        for question in self.questions.iter() {
            offset += question.write(&mut bytes[offset..])?;
        }
        for vec in [&self.answers, &self.authorities, &self.additional] {
            for answer in vec.iter() {
                offset += answer.write(&mut bytes[offset..])?;
            }
        }
        Ok(offset)
    }

    pub(crate) fn read(bytes: &[u8]) -> Result<(Self, usize), DnsError> {
        let header = Header::read(bytes)?;
        let mut questions: Vec<Question> = Vec::with_capacity(header.num_questions as usize);
        let mut answers: Vec<Answer> = Vec::with_capacity(header.num_answers as usize);
        let mut authorities: Vec<Answer> = Vec::with_capacity(header.num_authority as usize);
        let mut additional: Vec<Answer> = Vec::with_capacity(header.num_additional as usize);
        let mut offset = HEADER_SIZE;
        for _ in 0..header.num_questions {
            let (q, n) = Question::read(bytes, offset)?;
            offset = n;
            questions.push(q);
        }
        for (vec, vec_len) in [
            (&mut answers, header.num_answers),
            (&mut authorities, header.num_authority),
            (&mut additional, header.num_additional),
        ] {
            for _ in 0..vec_len {
                let (a, n) = Answer::read(bytes, offset)?;
                offset = n;
                vec.push(a);
            }
        }
        Ok((
            Self {
                header,
                questions,
                answers,
                authorities,
                additional,
            },
            offset,
        ))
    }
}

#[cfg_attr(test, derive(Clone, PartialEq, Debug))]
pub(crate) struct Header {
    id: u16,
    qr: bool,
    opcode: u8,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: u8,
    num_questions: u16,
    num_answers: u16,
    num_authority: u16,
    num_additional: u16,
}

impl Header {
    fn read(bytes: &[u8]) -> Result<Self, DnsError> {
        if bytes.len() < HEADER_SIZE {
            return Err(DnsError::TooSmall);
        }
        Ok(Self {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            qr: ((bytes[2] >> 7) & 0b1) != 0,
            opcode: ((bytes[2] >> 3) & 0b1111),
            authoritative_answer: ((bytes[2] >> 2) & 0b1) != 0,
            truncation: ((bytes[2] >> 1) & 0b1) != 0,
            recursion_desired: (bytes[2] & 0b1) != 0,
            recursion_available: ((bytes[3] >> 7) & 0b1) != 0,
            response_code: bytes[3] & 0b1111,
            num_questions: u16::from_be_bytes([bytes[4], bytes[5]]),
            num_answers: u16::from_be_bytes([bytes[6], bytes[7]]),
            num_authority: u16::from_be_bytes([bytes[8], bytes[9]]),
            num_additional: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    #[cfg(test)]
    fn write(&self, bytes: &mut [u8]) {
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2] = (((self.qr as u8) & 0b1) << 7)
            | ((self.opcode & 0b1111) << 3)
            | (((self.authoritative_answer as u8) & 0xb1) << 2)
            | (((self.truncation as u8) & 0b1) << 1)
            | ((self.recursion_desired as u8) & 0b1);
        bytes[3] = (((self.recursion_available as u8) & 0b1) << 7) | (self.response_code & 0b1111);
        bytes[4..6].copy_from_slice(&self.num_questions.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.num_answers.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.num_authority.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.num_additional.to_be_bytes());
    }
}

#[cfg_attr(test, derive(Clone, PartialEq, Debug))]
pub(crate) struct Question {
    pub(crate) name: Vec<u8>,
    pub(crate) query_type: u16,
    pub(crate) class: u16,
    pub(crate) name_offset: usize,
}

impl Question {
    fn read(all_bytes: &[u8], question_offset: usize) -> Result<(Self, usize), DnsError> {
        let (name, offset) = read_name(all_bytes, question_offset)?;
        if offset + 4 > all_bytes.len() {
            return Err(DnsError::TooSmall);
        }
        Ok((
            Self {
                name,
                query_type: u16::from_be_bytes([all_bytes[offset], all_bytes[offset + 1]]),
                class: u16::from_be_bytes([all_bytes[offset + 2], all_bytes[offset + 3]]),
                name_offset: question_offset,
            },
            offset + 4,
        ))
    }

    #[cfg(test)]
    fn write(&self, bytes: &mut [u8]) -> Result<usize, DnsError> {
        let offset = write_name(self.name.as_slice(), bytes)?;
        bytes[offset..(offset + 2)].copy_from_slice(&self.query_type.to_be_bytes());
        bytes[(offset + 2)..(offset + 4)].copy_from_slice(&self.class.to_be_bytes());
        Ok(offset + 4)
    }
}

#[cfg_attr(test, derive(Clone, PartialEq, Debug))]
pub(crate) struct Answer {
    pub(crate) name: Name,
    pub(crate) answer_type: u16,
    pub(crate) class: u16,
    pub(crate) ttl: i32, // should be positive
    pub(crate) data: Vec<u8>,
}

impl Answer {
    fn read(all_bytes: &[u8], answer_offset: usize) -> Result<(Self, usize), DnsError> {
        let (name, offset) = read_name(all_bytes, answer_offset)?;
        if offset + 10 > all_bytes.len() {
            return Err(DnsError::TooSmall);
        }
        let data_len = u16::from_be_bytes([all_bytes[offset + 8], all_bytes[offset + 9]]) as usize;
        if offset + 10 + data_len > all_bytes.len() {
            return Err(DnsError::TooSmall);
        }
        Ok((
            Self {
                name: Name::Bytes(name),
                answer_type: u16::from_be_bytes([all_bytes[offset], all_bytes[offset + 1]]),
                class: u16::from_be_bytes([all_bytes[offset + 2], all_bytes[offset + 3]]),
                ttl: i32::from_be_bytes([
                    all_bytes[offset + 4],
                    all_bytes[offset + 5],
                    all_bytes[offset + 6],
                    all_bytes[offset + 7],
                ]),
                data: all_bytes[(offset + 10)..(offset + 10 + data_len)].into(),
            },
            offset + 10 + data_len,
        ))
    }

    #[cfg(test)]
    fn write(&self, bytes: &mut [u8]) -> Result<usize, DnsError> {
        let offset = self.name.write(bytes)?;
        bytes[offset..(offset + 2)].copy_from_slice(&self.answer_type.to_be_bytes());
        bytes[(offset + 2)..(offset + 4)].copy_from_slice(&self.class.to_be_bytes());
        bytes[(offset + 4)..(offset + 8)].copy_from_slice(&self.ttl.to_be_bytes());
        bytes[(offset + 8)..(offset + 10)].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        bytes[(offset + 10)..(offset + 10 + self.data.len())].copy_from_slice(self.data.as_slice());
        Ok(offset + 10 + self.data.len())
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Debug))]
pub(crate) enum Name {
    Bytes(Vec<u8>),
}

impl Name {
    #[cfg(test)]
    fn write(&self, bytes: &mut [u8]) -> Result<usize, DnsError> {
        match self {
            Self::Bytes(vec) => write_name(vec.as_slice(), bytes),
        }
    }
}

fn write_name(name: &[u8], bytes: &mut [u8]) -> Result<usize, DnsError> {
    let name_len = name.len();
    Ok(if name_len == 0 {
        bytes[0] = name_len as u8;
        1
    } else {
        let mut offset = 0;
        for label in name.split(|b| *b == b'.') {
            let n = label.len();
            if n > MAX_LABEL_LEN {
                return Err(DnsError::TooSmall);
            }
            bytes[offset] = n as u8;
            bytes[(offset + 1)..(offset + 1 + n)].copy_from_slice(label);
            offset += n + 1;
        }
        bytes[offset] = 0; // zero octet
        offset + 1
    })
}

fn read_name(bytes: &[u8], question_offset: usize) -> Result<(Vec<u8>, usize), DnsError> {
    let mut name: Vec<u8> = Vec::with_capacity(MAX_NAME_LEN);
    let mut i = question_offset;
    let mut saved_offset: Option<usize> = None;
    loop {
        if i >= bytes.len() {
            return Err(DnsError::TooSmall);
        }
        let len = bytes[i];
        i += 1;
        if len == 0 {
            break;
        }
        // jump using the pointer
        if (len & 0b11000000) == 0b11000000 {
            if i >= bytes.len() {
                return Err(DnsError::TooSmall);
            }
            saved_offset = Some(i + 1);
            i = ((((len & 0b111111) as u16) << 8) | (bytes[i] as u16)) as usize;
            if i >= bytes.len() {
                return Err(DnsError::TooSmall);
            }
            continue;
        }
        let len = len as usize;
        if len > MAX_LABEL_LEN {
            return Err(DnsError::TooSmall);
        }
        if !name.is_empty() {
            name.push(b'.');
        }
        if i + len >= bytes.len() {
            return Err(DnsError::TooSmall);
        }
        name.extend_from_slice(&bytes[i..(i + len)]);
        i += len;
    }
    let offset = match saved_offset {
        Some(offset) => offset,
        None => i,
    };
    Ok((name, offset))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::net::Ipv4Addr;

    use quickcheck::Arbitrary;
    use rand::Rng;

    use super::*;

    #[quickcheck_macros::quickcheck]
    fn read_write_header(header: Header) {
        let mut bytes = [0_u8; HEADER_SIZE];
        header.write(&mut bytes[..]);
        let actual_header = Header::read(&bytes[..]).unwrap();
        assert_eq!(
            header, actual_header,
            "expected\n{:#?}\nactual\n{:#?}",
            header, actual_header
        );
    }

    impl Arbitrary for Header {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut prng = rand::thread_rng();
            Self {
                id: Arbitrary::arbitrary(g),
                qr: Arbitrary::arbitrary(g),
                opcode: prng.gen_range(0..((1 << 4) - 1)),
                authoritative_answer: Arbitrary::arbitrary(g),
                truncation: Arbitrary::arbitrary(g),
                recursion_desired: Arbitrary::arbitrary(g),
                recursion_available: Arbitrary::arbitrary(g),
                response_code: prng.gen_range(0..((1 << 4) - 1)),
                num_questions: Arbitrary::arbitrary(g),
                num_answers: Arbitrary::arbitrary(g),
                num_authority: Arbitrary::arbitrary(g),
                num_additional: Arbitrary::arbitrary(g),
            }
        }
    }

    #[quickcheck_macros::quickcheck]
    fn read_write_question(header: Header, question: Question) {
        let mut bytes = [0_u8; 512];
        header.write(&mut bytes[..]);
        question.write(&mut bytes[HEADER_SIZE..]).unwrap();
        let (actual_question, _) = Question::read(&bytes[..], HEADER_SIZE).unwrap();
        assert_eq!(question, actual_question);
    }

    impl Arbitrary for Question {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                name: TestName::arbitrary(g).data,
                class: Arbitrary::arbitrary(g),
                query_type: Arbitrary::arbitrary(g),
                name_offset: HEADER_SIZE,
            }
        }
    }

    fn do_read_write_name(name: &str) {
        let name: Vec<u8> = name.as_bytes().into();
        let mut bytes = [0_u8; 512];
        let offset = write_name(name.as_slice(), &mut bytes).unwrap();
        let (actual_name, actual_offset) = read_name(&bytes[..], 0).unwrap();
        assert_eq!(offset, actual_offset);
        assert_eq!(name, actual_name);
    }

    #[test]
    fn read_write_name_simple() {
        do_read_write_name("");
        do_read_write_name("x");
        do_read_write_name("x.y");
        do_read_write_name("x.y.z");
    }

    #[quickcheck_macros::quickcheck]
    fn read_write_name(name: TestName) {
        let mut bytes = [0_u8; 512];
        let offset = write_name(name.data.as_slice(), &mut bytes).unwrap();
        let (actual_name, actual_offset) = read_name(&bytes[..], 0).unwrap();
        assert_eq!(offset, actual_offset);
        assert_eq!(name.data, actual_name);
    }

    #[quickcheck_macros::quickcheck]
    fn read_write_answer(header: Header, answer: Answer) {
        let mut bytes = [0_u8; 512];
        header.write(&mut bytes[..]);
        answer.write(&mut bytes[HEADER_SIZE..]).unwrap();
        let (actual_answer, _) = Answer::read(&bytes[..], HEADER_SIZE).unwrap();
        assert_eq!(answer, actual_answer);
    }

    impl Arbitrary for Answer {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut data: Vec<u8> = Arbitrary::arbitrary(g);
            data.truncate(MAX_NAME_LEN);
            let mut prng = rand::thread_rng();
            Self {
                name: Name::Bytes(TestName::arbitrary(g).data),
                class: Arbitrary::arbitrary(g),
                answer_type: Arbitrary::arbitrary(g),
                ttl: prng.gen_range(0..i32::MAX),
                data,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestName {
        data: Vec<u8>,
    }

    impl Arbitrary for TestName {
        fn arbitrary(_: &mut quickcheck::Gen) -> Self {
            const LABEL_ALPHABET: &[u8; 27] = b"abcdefghijklmnopqrstuvwxyz-";
            let mut prng = rand::thread_rng();
            let nlabels: usize = prng.gen_range(0..3);
            let mut name = String::new();
            for label_index in 0..nlabels {
                let label_len: usize = prng.gen_range(1..MAX_LABEL_LEN);
                for _ in 0..label_len {
                    let i: usize = prng.gen_range(0..LABEL_ALPHABET.len());
                    name.push(LABEL_ALPHABET[i] as char);
                }
                if label_index != nlabels - 1 {
                    name.push('.');
                }
            }
            Self { data: name.into() }
        }
    }

    #[quickcheck_macros::quickcheck]
    fn read_write_packet(mut packet: DnsPacket) {
        let mut bytes = [0_u8; 4096];
        packet.write(&mut bytes[..]).unwrap();
        let (actual_packet, _) = DnsPacket::read(&bytes[..]).unwrap();
        assert_eq!(packet, actual_packet);
    }

    impl Arbitrary for DnsPacket {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut questions: Vec<Question> = Arbitrary::arbitrary(g);
            questions.truncate(1);
            let mut answers: Vec<Answer> = Arbitrary::arbitrary(g);
            answers.truncate(1);
            let mut authorities: Vec<Answer> = Arbitrary::arbitrary(g);
            authorities.truncate(1);
            let mut additional: Vec<Answer> = Arbitrary::arbitrary(g);
            additional.truncate(1);
            Self {
                header: Arbitrary::arbitrary(g),
                questions,
                answers,
                authorities,
                additional,
            }
        }
    }

    #[test]
    fn parse_real_query() {
        // nc -u -l -p 1053 > query
        // dig +retry=0 -p 1053 @127.0.0.1 +noedns staex.io
        // hexdump -b query
        const BYTES: [u8; 26] = [
            0o025, 0o013, 0o001, 0o040, 0o000, 0o001, 0o000, 0o000, 0o000, 0o000, 0o000, 0o000,
            0o005, 0o163, 0o164, 0o141, 0o145, 0o170, 0o002, 0o151, 0o157, 0o000, 0o000, 0o001,
            0o000, 0o001,
        ];
        let (packet, offset) = DnsPacket::read(&BYTES[..]).unwrap();
        assert_eq!(BYTES.len(), offset);
        assert_eq!(1, packet.header.num_questions);
        assert_eq!(0, packet.header.num_answers);
        assert_eq!(0, packet.header.num_authority);
        assert_eq!(0, packet.header.num_additional);
        assert_eq!(1, packet.questions.len());
        assert_eq!(0, packet.answers.len());
        assert_eq!(0, packet.authorities.len());
        assert_eq!(0, packet.additional.len());
        assert_eq!(b"staex.io".as_slice(), packet.questions[0].name.as_slice());
    }

    #[test]
    fn parse_real_answer() {
        // nc -u 8.8.8.8 53 < query > answer
        // hexdump -b answer
        const BYTES: [u8; 42] = [
            0o025, 0o013, 0o201, 0o200, 0o000, 0o001, 0o000, 0o001, 0o000, 0o000, 0o000, 0o000,
            0o005, 0o163, 0o164, 0o141, 0o145, 0o170, 0o002, 0o151, 0o157, 0o000, 0o000, 0o001,
            0o000, 0o001, 0o300, 0o014, 0o000, 0o001, 0o000, 0o001, 0o000, 0o000, 0o001, 0o054,
            0o000, 0o004, 0o271, 0o327, 0o004, 0o102,
        ];
        let (packet, offset) = DnsPacket::read(&BYTES[..]).unwrap();
        assert_eq!(BYTES.len(), offset);
        assert_eq!(1, packet.header.num_questions);
        assert_eq!(1, packet.header.num_answers);
        assert_eq!(0, packet.header.num_authority);
        assert_eq!(0, packet.header.num_additional);
        assert_eq!(1, packet.questions.len());
        assert_eq!(1, packet.answers.len());
        assert_eq!(0, packet.authorities.len());
        assert_eq!(0, packet.additional.len());
        assert_eq!(b"staex.io".as_slice(), packet.questions[0].name.as_slice());
        //assert_eq!(b"staex.io".as_slice(), packet.answers[0].name.as_slice());
        assert_eq!(1, packet.answers[0].answer_type);
        assert_eq!(1, packet.answers[0].class);
        assert_eq!(300, packet.answers[0].ttl);
        assert_eq!(4, packet.answers[0].data.len());
        let ipv4_addr: [u8; 4] = packet.answers[0].data[0..4].try_into().unwrap();
        assert_eq!(Ipv4Addr::new(185, 215, 4, 66), Ipv4Addr::from(ipv4_addr));
    }

    #[test]
    fn parse_non_existent_answer() {
        // nc -u 8.8.8.8 53 < query > answer
        // hexdump -b answer
        const BYTES: [u8; 105] = [
            0x3a, 0xef, 0x81, 0xa3, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x64,
            0x6f, 0x2d, 0x6e, 0x6f, 0x74, 0x2d, 0x65, 0x78, 0x69, 0x73, 0x74, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x50, 0xd3, 0x00, 0x40, 0x01,
            0x61, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73,
            0x03, 0x6e, 0x65, 0x74, 0x00, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65,
            0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67, 0x72, 0x73, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x78, 0x95, 0xa2, 0x90, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x03, 0x84, 0x00,
            0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80,
        ];
        let (packet, offset) = DnsPacket::read(&BYTES[..]).unwrap();
        assert_eq!(BYTES.len(), offset);
        assert_eq!(1, packet.header.num_questions);
        assert_eq!(0, packet.header.num_answers);
        assert_eq!(1, packet.header.num_authority);
        assert_eq!(0, packet.header.num_additional);
        assert_eq!(1, packet.questions.len());
        assert_eq!(0, packet.answers.len());
        assert_eq!(1, packet.authorities.len());
        assert_eq!(0, packet.additional.len());
        assert_eq!(3, packet.header.response_code);
    }

    #[test]
    fn parse_reverse_lookup_question() {
        // nc -u 8.8.8.8 53 < query > answer
        // hexdump -b answer
        const BYTES: [u8; 43] = [
            0x4b, 0xb2, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            0x37, 0x03, 0x32, 0x35, 0x35, 0x03, 0x32, 0x35, 0x35, 0x01, 0x35, 0x07, 0x69, 0x6e,
            0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00,
            0x01,
        ];
        let (packet, offset) = DnsPacket::read(&BYTES[..]).unwrap();
        assert_eq!(BYTES.len(), offset);
        assert_eq!(1, packet.header.num_questions);
        assert_eq!(0, packet.header.num_answers);
        assert_eq!(0, packet.header.num_authority);
        assert_eq!(0, packet.header.num_additional);
        assert_eq!(1, packet.questions.len());
        assert_eq!(0, packet.answers.len());
        assert_eq!(0, packet.authorities.len());
        assert_eq!(0, packet.additional.len());
        assert_eq!(0, packet.header.response_code);
        assert_eq!(12, packet.questions[0].query_type);
        assert_eq!(1, packet.questions[0].class);
    }

    #[test]
    fn parse_reverse_lookup_answer() {
        // nc -u 8.8.8.8 53 < query > answer
        // hexdump -b answer
        const BYTES: [u8; 66] = [
            0x4b, 0xb2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            0x37, 0x03, 0x32, 0x35, 0x35, 0x03, 0x32, 0x35, 0x35, 0x01, 0x35, 0x07, 0x69, 0x6e,
            0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x55, 0x00, 0x0b, 0x06,
            0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x02, 0x72, 0x75, 0x00,
        ];
        let (packet, offset) = DnsPacket::read(&BYTES[..]).unwrap();
        assert_eq!(BYTES.len(), offset);
        assert_eq!(1, packet.header.num_questions);
        assert_eq!(1, packet.header.num_answers);
        assert_eq!(0, packet.header.num_authority);
        assert_eq!(0, packet.header.num_additional);
        assert_eq!(1, packet.questions.len());
        assert_eq!(1, packet.answers.len());
        assert_eq!(0, packet.authorities.len());
        assert_eq!(0, packet.additional.len());
        assert_eq!(0, packet.header.response_code);
        assert_eq!(12, packet.answers[0].answer_type);
        assert_eq!(1, packet.answers[0].class);
    }

    #[test]
    fn parse_partial_packet() {
        // nc -u 8.8.8.8 53 < query > answer
        // hexdump -b answer
        const BYTES: [u8; 66] = [
            0x4b, 0xb2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            0x37, 0x03, 0x32, 0x35, 0x35, 0x03, 0x32, 0x35, 0x35, 0x01, 0x35, 0x07, 0x69, 0x6e,
            0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x55, 0x00, 0x0b, 0x06,
            0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x02, 0x72, 0x75, 0x00,
        ];
        for num_bytes in 0..BYTES.len() {
            let result = DnsPacket::read(&BYTES[..num_bytes]);
            if let Ok((packet, offset)) = result {
                panic!(
                    "expected error, got packet = {:?}, offset = {}",
                    packet, offset
                );
            }
        }
        if let Err(e) = DnsPacket::read(&BYTES[..]) {
            panic!("expected Ok(_), got error: {}", e);
        }
    }

    #[quickcheck_macros::quickcheck]
    fn parse_random_packet(bytes: Vec<u8>) {
        // we expect this test not to panic, otherwise the result could be anything
        let _result = DnsPacket::read(bytes.as_slice());
    }
}
