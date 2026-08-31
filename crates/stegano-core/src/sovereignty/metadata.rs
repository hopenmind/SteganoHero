//! Readable text metadata a plain-text or markdown document exposes.
//!
//! The native path reads only what sits in the text stream itself: a leading
//! byte-order mark, and a leading front-matter block. Metadata carried in a
//! binary container (PDF XMP, DOCX docProps, PNG iTXt) is out of scope for the
//! text path and belongs to the format bindings. This reader never claims to
//! see more than the text exposes.

/// Metadata read directly from the document's text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReadableMetadata {
    /// A byte-order mark sits at the very start of the document.
    pub leading_byte_order_mark: bool,
    /// A leading front-matter block, if present, as its raw inner lines.
    pub front_matter: Option<Vec<String>>,
}

/// Read the metadata the text exposes. Returns `None` when there is nothing to
/// report, so a caller can state plainly that no readable metadata was found.
pub fn read_metadata(document: &str) -> Option<ReadableMetadata> {
    let leading_byte_order_mark = document.starts_with('\u{FEFF}');
    let front_matter = read_front_matter(document);

    if !leading_byte_order_mark && front_matter.is_none() {
        return None;
    }

    Some(ReadableMetadata {
        leading_byte_order_mark,
        front_matter,
    })
}

/// A leading front-matter block is a `---` fence line, its content, and a
/// closing `---` fence line, at the very top of the document. Without a closing
/// fence there is no block, so the reader does not guess one.
fn read_front_matter(document: &str) -> Option<Vec<String>> {
    let body = document.strip_prefix('\u{FEFF}').unwrap_or(document);
    let mut lines = body.lines();

    if lines.next()? != "---" {
        return None;
    }

    let mut collected = Vec::new();
    for line in lines {
        if line == "---" {
            return Some(collected);
        }
        collected.push(line.to_string());
    }

    // Opening fence with no closing fence is not a front-matter block.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORPUS_MARKDOWN: &str = include_str!("../../../../tests/corpus/technical_markdown.md");
    const CORPUS_PLAIN: &str = include_str!("../../../../tests/corpus/en_short.txt");

    #[test]
    fn plain_text_exposes_no_metadata() {
        assert_eq!(read_metadata(CORPUS_PLAIN), None);
    }

    #[test]
    fn corpus_markdown_has_no_front_matter() {
        // The corpus markdown opens on a heading, not a fence.
        assert_eq!(read_metadata(CORPUS_MARKDOWN), None);
    }

    #[test]
    fn a_front_matter_block_is_read_as_metadata() {
        let doc = "---\ntitle: Notice\nauthor: Someone\n---\n# Body\n";
        let meta = read_metadata(doc).expect("front matter is present");
        assert!(!meta.leading_byte_order_mark);
        assert_eq!(
            meta.front_matter,
            Some(vec!["title: Notice".to_string(), "author: Someone".to_string()])
        );
    }

    #[test]
    fn an_opening_fence_without_a_closing_one_is_not_metadata() {
        let doc = "---\ntitle: Notice\nstill going\n";
        assert_eq!(read_metadata(doc), None);
    }

    #[test]
    fn a_leading_byte_order_mark_is_reported() {
        let doc = "\u{FEFF}Plain body with no fence.";
        let meta = read_metadata(doc).expect("a byte-order mark is present");
        assert!(meta.leading_byte_order_mark);
        assert_eq!(meta.front_matter, None);
    }

    #[test]
    fn a_mid_document_byte_order_mark_is_not_a_leading_one() {
        // already_carrying.txt holds U+FEFF mid-document on purpose. That is a
        // whitespace-variation mark, not document metadata.
        let doc = "Body first\u{FEFF} then more.";
        assert_eq!(read_metadata(doc), None);
    }
}
