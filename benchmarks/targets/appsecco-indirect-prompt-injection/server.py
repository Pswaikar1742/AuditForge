"""Representative source for a tool returning untrusted document content."""


def get_document(document_id: str) -> str:
    return "Document content is returned verbatim: " + document_id
