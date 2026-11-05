//! Registry-specific WHOIS query construction and interpretation.
//!
//! Choose [`ripe`] or [`denic`] explicitly. Core WHOIS owns raw queries and
//! framing; these helpers give registry flags their meaning.

use fictionet::stdlib::protocols::whois::{self, Query};

/// Why a registry query cannot be constructed or interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The raw WHOIS query is invalid.
    Query(whois::Error),
    /// The helper does not recognize a flag.
    UnknownFlag,
    /// A flag needs an argument that was not supplied.
    MissingArgument,
    /// An argument is empty, contains whitespace, or has an unsupported value.
    Argument,
    /// Search text begins with a flag and would be interpreted as one.
    Terms,
}

fictionet::error_display!(Error, f, {
    Error::Query(error) => error.fmt(f),
    Error::UnknownFlag => f.write_str("unknown registry flag"),
    Error::MissingArgument => f.write_str("missing registry flag argument"),
    Error::Argument => f.write_str("invalid registry flag argument"),
    Error::Terms => f.write_str("search text begins with a registry flag"),
});

fn word<'a>(rest: &mut &'a str) -> Option<&'a str> {
    *rest = rest.trim_start_matches([' ', '\t']);
    if rest.is_empty() {
        return None;
    }
    let end = rest.find([' ', '\t']).unwrap_or(rest.len());
    let value = &rest[..end];
    *rest = &rest[end..];
    Some(value)
}

fn is_flag(text: &str) -> bool {
    text.starts_with('-') && text.len() > 1 && !text[1..].starts_with([' ', '\t'])
}

fn append(text: &mut String, value: &str) -> Result<(), Error> {
    if text.len().saturating_add(value.len()) > whois::MAX_QUERY {
        return Err(Error::Query(whois::Error::QueryTooLong));
    }
    text.push_str(value);
    Ok(())
}

fn build<'a>(
    flags: impl Iterator<Item = (&'static str, Option<&'a str>)>,
    terms: &str,
) -> Result<Query, Error> {
    let terms = terms.trim_matches([' ', '\t']);
    if is_flag(terms) {
        return Err(Error::Terms);
    }
    let mut text = String::new();
    for (name, argument) in flags {
        append(&mut text, name)?;
        append(&mut text, " ")?;
        if let Some(argument) = argument {
            append(&mut text, argument)?;
            append(&mut text, " ")?;
        }
    }
    append(&mut text, terms)?;
    Query::new(&text).map_err(Error::Query)
}

/// RIPE database flags. In particular, `-C` never consumes an argument.
pub mod ripe {
    use super::{Error, Query, is_flag, word};

    /// One nonempty RIPE argument, with no spaces, tabs, or control characters.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Argument<'a>(&'a str);

    impl<'a> Argument<'a> {
        /// Validate a single argument without interpreting its registry data.
        pub fn new(text: &'a str) -> Result<Self, Error> {
            if text.is_empty() || text.contains([' ', '\t']) {
                return Err(Error::Argument);
            }
            if text.len() > super::whois::MAX_QUERY {
                return Err(Error::Query(super::whois::Error::QueryTooLong));
            }
            if let Some(c) = text.chars().find(|c| c.is_control()) {
                return Err(Error::Query(super::whois::Error::Control(c)));
            }
            Ok(Self(text))
        }

        /// The original argument text.
        pub fn as_str(self) -> &'a str {
            self.0
        }
    }

    /// Server information selected by `-q`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum QueryKind {
        /// Server software version.
        Version,
        /// Recognized object types.
        Types,
        /// Available database sources.
        Sources,
    }

    impl QueryKind {
        fn new(text: &str) -> Result<Self, Error> {
            match text {
                "version" => Ok(Self::Version),
                "types" => Ok(Self::Types),
                "sources" => Ok(Self::Sources),
                _ => Err(Error::Argument),
            }
        }

        fn as_str(self) -> &'static str {
            match self {
                Self::Version => "version",
                Self::Types => "types",
                Self::Sources => "sources",
            }
        }
    }

    /// Response encoding requested from RIPE, including other named encodings.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Charset<'a> {
        /// UTF-8.
        Utf8,
        /// ISO-8859-1.
        Latin1,
        /// Another encoding name supplied by the caller.
        Other(Argument<'a>),
    }

    impl<'a> Charset<'a> {
        fn new(text: &'a str) -> Result<Self, Error> {
            match text {
                s if s.eq_ignore_ascii_case("UTF-8") => Ok(Self::Utf8),
                s if s.eq_ignore_ascii_case("ISO-8859-1") => Ok(Self::Latin1),
                _ => Ok(Self::Other(Argument::new(text)?)),
            }
        }

        fn as_str(self) -> &'a str {
            match self {
                Self::Utf8 => "UTF-8",
                Self::Latin1 => "ISO-8859-1",
                Self::Other(value) => value.as_str(),
            }
        }
    }

    /// A decimal historical revision number, preserving its original spelling.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Revision<'a>(&'a str);

    impl<'a> Revision<'a> {
        /// Read a nonempty sequence of decimal digits without a machine-size limit.
        pub fn new(text: &'a str) -> Result<Self, Error> {
            let value = Argument::new(text)?;
            if !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Argument);
            }
            Ok(Self(value.as_str()))
        }

        /// The original revision number.
        pub fn as_str(self) -> &'a str {
            self.0
        }
    }

    /// Two historical revision numbers separated by a colon, in comparison order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Revisions<'a>(&'a str);

    impl<'a> Revisions<'a> {
        /// Read two decimal revision numbers without imposing an ordering.
        pub fn new(text: &'a str) -> Result<Self, Error> {
            let value = Argument::new(text)?;
            let (before, after) = text.split_once(':').ok_or(Error::Argument)?;
            Revision::new(before)?;
            Revision::new(after)?;
            Ok(Self(value.as_str()))
        }

        /// The original pair of revision numbers.
        pub fn as_str(self) -> &'a str {
            self.0
        }
    }

    macro_rules! flags {
        ($( $bare:ident: $short:literal, $long:literal; )* ;
         $( $arg:ident($value:ty): $arg_short:literal $(, $arg_long:literal)*; )*) => {
            /// Known RIPE flags and their single-word argument values.
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum Flag<'a> {
                $(#[doc = concat!("The `", $short, "` / `", $long, "` flag.")]
                $bare,)*
                $(#[doc = concat!("The `", $arg_short, "` argument.")]
                $arg($value),)*
            }

            impl<'a> Flag<'a> {
                fn read(name: &str, argument: impl FnOnce() -> Result<&'a str, Error>) -> Result<Self, Error> {
                    Ok(match name {
                        $($short | $long => Self::$bare,)*
                        $($arg_short $(| $arg_long)* => Self::$arg(<$value>::new(argument()?)?),)*
                        _ => return Err(Error::UnknownFlag),
                    })
                }

                fn parts(self) -> (&'static str, Option<&'a str>) {
                    match self {
                        $(Self::$bare => ($short, None),)*
                        $(Self::$arg(value) => ($arg_short, Some(value.as_str())),)*
                    }
                }
            }
        };
    }

    flags! {
        Unfiltered: "-B", "--no-filtering";
        NoRelated: "-r", "--no-referenced";
        NoIrt: "-C", "--no-irt";
        ;
        Inverse(Argument<'a>): "-i", "--inverse";
        Types(Argument<'a>): "-T", "--select-types";
        Sources(Argument<'a>): "-s", "--sources";
        Resources(Argument<'a>): "-S", "--resources";
        Template(Argument<'a>): "-t", "--template";
        Verbose(Argument<'a>): "-v", "--verbose";
        Query(QueryKind): "-q";
        Client(Argument<'a>): "-V", "--client";
        Changes(Argument<'a>): "-g";
        Version(Revision<'a>): "--show-version";
        DiffVersions(Revisions<'a>): "--diff-versions";
        Charset(Charset<'a>): "-Z", "--charset";
    }

    /// Construct a query from typed flags and search text.
    pub fn build(flags: &[Flag<'_>], terms: &str) -> Result<Query, Error> {
        super::build(flags.iter().map(|flag| flag.parts()), terms)
    }

    /// Interpret known RIPE flags, including grouped short flags.
    /// Unknown flags and missing arguments are errors. Search text is trimmed.
    pub fn parse(query: &Query) -> Result<(Vec<Flag<'_>>, &str), Error> {
        let mut rest = query.as_str().trim_matches([' ', '\t']);
        let mut flags = Vec::new();
        while is_flag(rest) {
            let name = word(&mut rest).unwrap();
            if name.starts_with("--") {
                flags.push(Flag::read(name, || {
                    word(&mut rest).ok_or(Error::MissingArgument)
                })?);
            } else {
                let mut group = &name[1..];
                while !group.is_empty() {
                    let end = group.chars().next().unwrap().len_utf8();
                    let short = format!("-{}", &group[..end]);
                    group = &group[end..];
                    flags.push(Flag::read(&short, || {
                        if group.is_empty() {
                            word(&mut rest).ok_or(Error::MissingArgument)
                        } else {
                            Ok(std::mem::take(&mut group))
                        }
                    })?);
                }
            }
            rest = rest.trim_start_matches([' ', '\t']);
        }
        Ok((flags, rest))
    }
}

/// DENIC domain queries. `-C` always consumes a supported character set.
pub mod denic {
    use super::{Error, Query, is_flag, word};

    /// Character sets accepted by DENIC's `-C` flag.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Charset {
        /// UTF-8.
        Utf8,
        /// ISO-8859-1.
        Latin1,
        /// US-ASCII.
        Ascii,
    }

    impl Charset {
        fn text(self) -> &'static str {
            match self {
                Self::Utf8 => "UTF-8",
                Self::Latin1 => "ISO-8859-1",
                Self::Ascii => "US-ASCII",
            }
        }

        fn parse(text: &str) -> Result<Self, Error> {
            match text {
                s if s.eq_ignore_ascii_case("UTF-8") => Ok(Self::Utf8),
                s if s.eq_ignore_ascii_case("ISO-8859-1") => Ok(Self::Latin1),
                s if s.eq_ignore_ascii_case("US-ASCII") => Ok(Self::Ascii),
                _ => Err(Error::Argument),
            }
        }
    }

    /// Domain representations requested by DENIC's `-T` flag.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Types {
        /// Domain name.
        Domain,
        /// ASCII compatible encoding.
        Ace,
        /// Both domain name and ASCII compatible encoding.
        DomainAndAce,
    }

    impl Types {
        fn text(self) -> &'static str {
            match self {
                Self::Domain => "dn",
                Self::Ace => "ace",
                Self::DomainAndAce => "dn,ace",
            }
        }

        fn parse(text: &str) -> Result<Self, Error> {
            match text {
                "dn" => Ok(Self::Domain),
                "ace" => Ok(Self::Ace),
                "dn,ace" => Ok(Self::DomainAndAce),
                _ => Err(Error::Argument),
            }
        }
    }

    /// Known DENIC query flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Flag {
        /// Select the response character set.
        Charset(Charset),
        /// Select domain representations.
        Types(Types),
    }

    /// Construct a DENIC query from typed flags and search text.
    pub fn build(flags: &[Flag], terms: &str) -> Result<Query, Error> {
        super::build(
            flags.iter().map(|flag| match flag {
                Flag::Charset(charset) => ("-C", Some(charset.text())),
                Flag::Types(types) => ("-T", Some(types.text())),
            }),
            terms,
        )
    }

    /// Interpret DENIC flags without guessing from a possible search term.
    pub fn parse(query: &Query) -> Result<(Vec<Flag>, &str), Error> {
        let mut rest = query.as_str().trim_matches([' ', '\t']);
        let mut flags = Vec::new();
        while is_flag(rest) {
            let name = word(&mut rest).unwrap();
            flags.push(match name {
                "-C" => Flag::Charset(Charset::parse(
                    word(&mut rest).ok_or(Error::MissingArgument)?,
                )?),
                "-T" => Flag::Types(Types::parse(
                    word(&mut rest).ok_or(Error::MissingArgument)?,
                )?),
                _ => return Err(Error::UnknownFlag),
            });
            rest = rest.trim_start_matches([' ', '\t']);
        }
        Ok((flags, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Wire;

    #[test]
    fn registry_selects_the_meaning_of_c() {
        let query = Query::new("-C utf-8 example.de").unwrap();
        assert_eq!(
            ripe::parse(&query),
            Ok((vec![ripe::Flag::NoIrt], "utf-8 example.de"))
        );
        assert_eq!(
            denic::parse(&query),
            Ok((
                vec![denic::Flag::Charset(denic::Charset::Utf8)],
                "example.de"
            ))
        );
        let query = Query::new("-C 193.0.0.1").unwrap();
        assert_eq!(
            ripe::parse(&query),
            Ok((vec![ripe::Flag::NoIrt], "193.0.0.1"))
        );
        assert_eq!(denic::parse(&query), Err(Error::Argument));
        assert_eq!(
            ripe::parse(&Query::new("-C AS3333 x").unwrap()).unwrap().1,
            "AS3333 x"
        );
    }

    #[test]
    fn ripe_flags_and_groups() {
        use ripe::Flag::{
            Charset, DiffVersions, Inverse, NoRelated, Resources, Sources, Types, Unfiltered,
            Version,
        };
        for (text, flags, terms) in [
            (
                "-B -T inetnum 193.0.0.1",
                vec![Unfiltered, Types(ripe::Argument::new("inetnum").unwrap())],
                "193.0.0.1",
            ),
            (
                "  --sources\tRIPE  -r   AS3333  ",
                vec![Sources(ripe::Argument::new("RIPE").unwrap()), NoRelated],
                "AS3333",
            ),
            (
                "-Bi tech-c DW-RIPE",
                vec![Unfiltered, Inverse(ripe::Argument::new("tech-c").unwrap())],
                "DW-RIPE",
            ),
            (
                "-Tas-set AS-FOO",
                vec![Types(ripe::Argument::new("as-set").unwrap())],
                "AS-FOO",
            ),
            ("-rB AS3333", vec![NoRelated, Unfiltered], "AS3333"),
            (
                "-Z UTF-8 AS3333",
                vec![Charset(ripe::Charset::Utf8)],
                "AS3333",
            ),
            (
                "--charset UTF-8 AS3333",
                vec![Charset(ripe::Charset::Utf8)],
                "AS3333",
            ),
            (
                "-S ARIN-GRS 193.201.1.1",
                vec![Resources(ripe::Argument::new("ARIN-GRS").unwrap())],
                "193.201.1.1",
            ),
            (
                "--show-version 2 AS3333",
                vec![Version(ripe::Revision::new("2").unwrap())],
                "AS3333",
            ),
            (
                "--diff-versions 1:2 AS3333",
                vec![DiffVersions(ripe::Revisions::new("1:2").unwrap())],
                "AS3333",
            ),
        ] {
            assert_eq!(
                ripe::parse(&Query::new(text).unwrap()),
                Ok((flags.clone(), terms))
            );
            let query = ripe::build(&flags, terms).unwrap();
            assert_eq!(ripe::parse(&query), Ok((flags, terms)));
            assert_eq!(Query::parse(&query.to_bytes().unwrap()), Ok(query));
        }
        assert_eq!(
            ripe::parse(&Query::new("-i").unwrap()),
            Err(Error::MissingArgument)
        );
        assert_eq!(
            ripe::parse(&Query::new("--unknown x").unwrap()),
            Err(Error::UnknownFlag)
        );
    }

    #[test]
    fn denic_types_and_charsets() {
        use denic::{Charset, Flag, Types};
        for charset in [Charset::Utf8, Charset::Latin1, Charset::Ascii] {
            for types in [Types::Domain, Types::Ace, Types::DomainAndAce] {
                let flags = [Flag::Types(types), Flag::Charset(charset)];
                let query = denic::build(&flags, " example.de ").unwrap();
                assert_eq!(denic::parse(&query), Ok((flags.to_vec(), "example.de")));
                assert_eq!(Query::parse(&query.to_bytes().unwrap()), Ok(query));
            }
        }
        let query = Query::new("-T dn,ace -C UTF-8 example.de").unwrap();
        assert_eq!(
            denic::parse(&query),
            Ok((
                vec![
                    Flag::Types(Types::DomainAndAce),
                    Flag::Charset(Charset::Utf8)
                ],
                "example.de"
            ))
        );
        assert_eq!(
            denic::parse(&Query::new("-C").unwrap()),
            Err(Error::MissingArgument)
        );
        assert_eq!(
            denic::parse(&Query::new("-T").unwrap()),
            Err(Error::MissingArgument)
        );
        assert_eq!(
            denic::parse(&Query::new("-T inetnum x").unwrap()),
            Err(Error::Argument)
        );
        assert_eq!(
            denic::parse(&Query::new("-B x").unwrap()),
            Err(Error::UnknownFlag)
        );
    }

    #[test]
    fn ripe_argument_values_are_typed() {
        for kind in [
            ripe::QueryKind::Version,
            ripe::QueryKind::Types,
            ripe::QueryKind::Sources,
        ] {
            let flags = [ripe::Flag::Query(kind)];
            let query = ripe::build(&flags, "").unwrap();
            assert_eq!(ripe::parse(&query), Ok((flags.to_vec(), "")));
        }
        for (text, charset) in [
            ("utf-8", ripe::Charset::Utf8),
            ("ISO-8859-1", ripe::Charset::Latin1),
            (
                "US-ASCII",
                ripe::Charset::Other(ripe::Argument::new("US-ASCII").unwrap()),
            ),
        ] {
            let query = Query::new(&format!("-Z {text} AS3333")).unwrap();
            let flags = vec![ripe::Flag::Charset(charset)];
            assert_eq!(ripe::parse(&query), Ok((flags.clone(), "AS3333")));
            let query = ripe::build(&flags, "AS3333").unwrap();
            assert_eq!(ripe::parse(&query), Ok((flags, "AS3333")));
        }
        for text in [
            "-q unknown",
            "--show-version garbage AS3333",
            "--show-version -1 AS3333",
            "--diff-versions 1:two AS3333",
            "--diff-versions 1:2:3 AS3333",
            "--diff-versions :2 AS3333",
            "--diff-versions 1: AS3333",
        ] {
            assert_eq!(
                ripe::parse(&Query::new(text).unwrap()),
                Err(Error::Argument)
            );
        }
        let flags = [
            ripe::Flag::Version(ripe::Revision::new("0002").unwrap()),
            ripe::Flag::DiffVersions(ripe::Revisions::new("11:10").unwrap()),
        ];
        let query = ripe::build(&flags, "AS3333").unwrap();
        assert_eq!(
            query.as_str(),
            "--show-version 0002 --diff-versions 11:10 AS3333"
        );
        assert_eq!(ripe::parse(&query), Ok((flags.to_vec(), "AS3333")));
    }

    #[test]
    fn terms_stay_raw_after_flags() {
        for terms in [
            "n + 8.8.8.8",
            "domain example.com",
            "=example.com",
            "- x",
            "",
            "AS3333 -r",
        ] {
            let query = ripe::build(&[], terms).unwrap();
            assert_eq!(ripe::parse(&query), Ok((vec![], terms)));
            let query = denic::build(&[], terms).unwrap();
            assert_eq!(denic::parse(&query), Ok((vec![], terms)));
        }
        assert_eq!(
            ripe::build(&[ripe::Flag::Unfiltered], "").unwrap().as_str(),
            "-B "
        );
        assert_eq!(ripe::build(&[], "-r x"), Err(Error::Terms));
        assert_eq!(denic::build(&[], "-C UTF-8"), Err(Error::Terms));
        for argument in ["", "a b", "a\tb"] {
            assert_eq!(ripe::Argument::new(argument), Err(Error::Argument));
        }
    }

    #[test]
    fn builders_preserve_wire_limits_and_control_rejection() {
        for c in ['\r', '\n', '\0'] {
            let terms = format!("a{c}b");
            assert_eq!(
                ripe::build(&[], &terms),
                Err(Error::Query(whois::Error::Control(c)))
            );
            assert_eq!(
                denic::build(&[], &terms),
                Err(Error::Query(whois::Error::Control(c)))
            );
            assert_eq!(
                ripe::Argument::new(&terms),
                Err(Error::Query(whois::Error::Control(c)))
            );
        }
        let limit = whois::MAX_QUERY;
        assert_eq!(
            ripe::build(&[], &"a".repeat(limit)).unwrap().as_str().len(),
            limit
        );
        assert_eq!(
            denic::build(&[], &"a".repeat(limit))
                .unwrap()
                .as_str()
                .len(),
            limit
        );
        assert_eq!(
            ripe::build(&[ripe::Flag::Unfiltered; 2000], ""),
            Err(Error::Query(whois::Error::QueryTooLong))
        );
        assert_eq!(
            ripe::build(
                &[ripe::Flag::Types(
                    ripe::Argument::new(&"a".repeat(limit)).unwrap()
                )],
                "b"
            ),
            Err(Error::Query(whois::Error::QueryTooLong))
        );
        assert_eq!(
            denic::build(
                &[denic::Flag::Charset(denic::Charset::Utf8)],
                &"a".repeat(limit)
            ),
            Err(Error::Query(whois::Error::QueryTooLong))
        );
    }
}
