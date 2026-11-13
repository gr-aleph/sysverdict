"""Log text made safe for the page: escaping, addresses shown as code text (never links),
and program names as written in the log."""

import html
import re


FILE_ENDINGS = {"exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "msi", "lnk", "rtf",
                "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "mp4", "tmp",
                "dat", "log", "ini", "json", "csv", "png", "jpg", "evtx"}


# A domain (ending in a 2-6 letter top-level domain such as .com or .sg) or an IPv4 address.
# Two patterns joined by | ("or"):
#   domain: (?:[a-z0-9-]+\.)+ = one or more name parts that each end in a dot ("www.", "example."),
#           then [a-z]{2,6} = an ending of 2-6 letters ("com"). \b = a word edge.
#   IPv4:   \d{1,3} = 1-3 digits, then (?:\.\d{1,3}){3} = three more ".digits" groups,
#           then (?::\d{1,5})? = an optional port such as ":80".
DOMAIN_OR_IP = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,6}\b|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b",
                          re.IGNORECASE)


# A full URL, a domain or an IPv4 address (a URL is matched whole, before its domain).
# URL: "http" or "https", "://", then the shortest run of characters that are not spaces,
# quotes or angle brackets (+?), stopping where an optional final punctuation mark
# (. , ; : ) ]) is followed by a space or the end of the text. So in "visit https://a.com/x."
# the URL is "https://a.com/x" without the sentence's full stop.
URL = r"https?://[^\s<>\"'`]+?(?=[.,;:)\]]?(?:\s|$))"


ADDRESS = re.compile(f"{URL}|{DOMAIN_OR_IP.pattern}", re.IGNORECASE)


def code_addresses(text):
    """Wrap URLs, domains and IPs in <code> tags for the page: shown exactly as in the log,
    but never turned into a clickable link. File names are left alone.
    HTML tags (not Markdown backticks) work both in Markdown text and inside HTML blocks
    such as the Findings cards, where Markdown is not processed."""
    def wrap(match):
        token = match.group(0)
        is_url = token.lower().startswith("http")
        if not is_url and token.rsplit(".", 1)[-1].lower() in FILE_ENDINGS:
            return token
        return f"<code>{token}</code>"
    return ADDRESS.sub(wrap, text)


# Characters that Markdown (and Streamlit's math) would turn into a link, an image, bold text,
# a heading, code or a formula. Each is replaced by its HTML number (&#91; shows as "["), so the
# browser shows the character but Markdown does not act on it. "$" starts a formula in Streamlit.
MARKDOWN_CHARACTERS = {"[": "&#91;", "]": "&#93;", "(": "&#40;", ")": "&#41;", "!": "&#33;",
                       "*": "&#42;", "_": "&#95;", "#": "&#35;", "`": "&#96;", "~": "&#126;",
                       "|": "&#124;", "$": "&#36;"}


def esc(text):
    """Log text made safe for the page:
    1. html.escape, so a crafted log cannot inject HTML;
    2. Markdown characters replaced (one character at a time), so "[Click](https://x)" or
       "![x](http://1.2.3.4/p)" is shown as text, never as a link or a loaded image;
    3. URLs, domains and IPs wrapped in <code>, which is never a clickable link;
    4. line breaks shown as <br>."""
    text = html.escape(str(text), quote=False)
    text = "".join(MARKDOWN_CHARACTERS.get(character, character) for character in text)
    return code_addresses(text).replace("\n", "<br>")


def display_name(path):
    """File name as written in the log (keeps its capitals): 'C:\\x\\FireEye.exe' -> 'FireEye.exe'."""
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1]
