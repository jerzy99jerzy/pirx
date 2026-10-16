#!/usr/bin/env python3
"""Render `docs/MANUAL.md` as the project's GitHub Pages site.

    python -m tools.build_site                      build ./_site, links at main
    python -m tools.build_site --ref SHA --out DIR  what pages.yml runs

One HTML file, one stylesheet, the README's banner and the manual's diagrams:
no script, no web font, nothing fetched from any other origin, so a reader's
browser makes no request the reader did not choose. The page is a copy. The
file in the repository is the source, and the page names the commit it was
copied from.

Ported from cve-digest's builder of the same name (its 0.7.19.4 and 0.7.19.5),
restated here rather than vendored, as FAMILY.md 3.5 asks of process
artefacts. What differs is listed so a reader of both does not have to diff
them: the source, the codename and banner, the description (taken from
`pyproject.toml`, because the manual opens with an epigraph rather than a
summary sentence), and the diagrams, which cve-digest's manual does not have.

**Diagrams.** The manual carries Mermaid blocks, and GitHub draws them with a
script. This page runs none, so each block is drawn once, by hand, into an
SVG under `docs/site/diagrams/` named for the SHA-256 of the block's source
bytes, and the page shows that file with the source beneath it. A block whose
source has no file of that name is refused: an edited diagram without a new
drawing fails the gate instead of publishing a stale picture. The drawing was
made with mermaid-cli, which is not a dependency of anything here:

    npm install @mermaid-js/mermaid-cli@12.0.0     (bundles mermaid 12.2.0)
    mmdc -t dark -b '#0d1117' -i BLOCK.mmd -o SHA256.svg

with BLOCK.mmd holding exactly the lines between the fences, each ending in a
newline. `tests/test_site.py` refuses an SVG under `docs/site/diagrams/` that
no block names, so a redrawn diagram does not leave its predecessor behind.

An SVG is a document, and opened directly from the site it runs with the
site's origin, outside the page's Content-Security-Policy. So a drawing is
refused unless it is made only of the elements and attributes mermaid-cli
wrote for these three diagrams, and holds nothing that reads as script or a
fetch; `svg_problems` lists the checks. Mermaid's output for these diagrams
passes; a `click` link, which Mermaid writes as an outside `href`, would not.

The header carries the codename the way the README does, with the same file,
`docs/assets/pirx-banner.gif`. It animates, so a reader who asked their
system for reduced motion gets `docs/site/pirx-banner-still.png` instead, the
GIF's first frame. That still was exported once with Pillow, also not a
dependency of anything here:

    Image.open(gif).convert("RGB").quantize(256).save(png, optimize=True)

and `tests/test_site.py` holds its size to the GIF's, read from both headers,
so a new banner without a new still fails the gate.

The build is also the check. A page that would publish wrong is refused rather
than written, with every problem listed, not only the first:

- A table row with more cells than its header. Under the GFM table rule a `|`
  splits a cell even inside a code span, and a cell past the header's last
  column is dropped without a word, so the row renders cut short on GitHub and
  here alike. The fix is `\\|`.
- A relative link to a path that is not in the tree, a link that is neither
  `https:` nor relative, and a `#` link that names no heading on the page.
- An image, which this builder does not copy and would publish broken.
- A heading that holds a link, because the heading itself becomes one.
- A diagram without a drawing, or with one that fails the checks above.

Raw HTML in the source is escaped, not rendered: the page carries only the
markup this file writes. Relative links become links into the repository at
the commit the page was built from, so a reader who follows one sees the tree
the page describes.

`tests/test_site.py` builds the real manual, so an edit that would publish
broken fails the gate before it reaches `main`. Exit codes: 0 built, 1 the
document failed a check, 2 the builder could not run.

Does NOT:
  - run anything at runtime. `pirx` imports nothing from here, and the
    package's zero-dependency claim is about the package: the parser below is
    a build dependency, pinned by hash in `requirements-docs.txt`.
  - draw diagrams. It checks and copies drawings a person made.
  - prove the page matches GitHub's rendering. It refuses the known ways a
    page publishes wrong; a new way is a new check.

Needs `markdown-it-py`: `requirements-docs.txt`, for the workflow and for the
gate's test job alike.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import posixpath
import re
import shutil
import string
import struct
import sys
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.common.utils import escapeHtml
from markdown_it.renderer import RendererHTML
from markdown_it.token import Token

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "MANUAL.md"
SITE = ROOT / "docs" / "site"
TEMPLATE = SITE / "template.html"
STYLESHEET = SITE / "site.css"
DIAGRAMS = SITE / "diagrams"
BANNER = ROOT / "docs" / "assets" / "pirx-banner.gif"
BANNER_STILL = SITE / "pirx-banner-still.png"
PYPROJECT = ROOT / "pyproject.toml"
REPOSITORY = "jerzy99jerzy/pirx"
CODENAME = "Pirx"

# A ref and a repository name land in URLs and in the page. CI supplies both
# and they are still checked: an input trusted today is the one nobody re-reads
# when the workflow that supplies it changes.
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
_SHA = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_VIEWBOX = re.compile(r"\s*-?[\d.]+[\s,]+-?[\d.]+[\s,]+([\d.]+)[\s,]+([\d.]+)\s*")


class SiteError(Exception):
    """The document failed one or more checks; carries all of them."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = list(problems)


@dataclass
class Heading:
    level: int
    anchor: str
    html: str


@dataclass
class Diagram:
    digest: str
    width: int
    height: int

    @property
    def name(self) -> str:
        return f"{self.digest}.svg"


@dataclass
class Page:
    title: str
    title_html: str
    body: str
    toc: list[Heading] = field(default_factory=list)
    diagrams: list[Diagram] = field(default_factory=list)


# --- anchors -----------------------------------------------------------------


def slug(text: str) -> str:
    """GitHub's heading anchor rule for ASCII headings: lowercase, keep
    letters, digits, `_`, `-` and spaces, then hyphenate the spaces, as
    github-slugger does, so a fragment copied from the file's page on GitHub
    works here. Not exact beyond ASCII: `str.isalnum` drops combining marks
    and connector punctuation that github-slugger keeps. Every heading in the
    manual is ASCII today."""
    kept = "".join(ch for ch in text.lower() if ch.isalnum() or ch in "-_ ")
    return kept.replace(" ", "-")


class Slugger:
    """Repeated headings get `-1`, `-2` in document order, as on GitHub."""

    def __init__(self) -> None:
        self.seen: dict[str, int] = {}

    def __call__(self, text: str) -> str:
        base = slug(text)
        result = base
        while result in self.seen:
            self.seen[base] += 1
            result = f"{base}-{self.seen[base]}"
        self.seen[result] = 0
        return result


def plain(children: Sequence[Token] | None) -> str:
    """The text a reader sees in an inline run, code spans included."""
    parts: list[str] = []
    for child in children or ():
        if child.type in ("text", "code_inline"):
            parts.append(child.content)
        elif child.type in ("softbreak", "hardbreak"):
            parts.append(" ")
    return "".join(parts)


# --- the table rule ----------------------------------------------------------


def cells(row: str) -> int:
    """Cells in one table row by the GFM rule: a pipe at either end is not a
    separator, an escaped one never is, and nothing else protects a pipe, a
    code span included."""
    text = row.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|") and not text.endswith("\\|"):
        text = text[:-1]
    count, i = 1, 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "|":
            count += 1
        i += 1
    return count


def table_problems(
    tokens: Sequence[Token], lines: Sequence[str], name: str
) -> list[str]:
    problems: list[str] = []
    for tok in tokens:
        if tok.type != "table_open" or not tok.map:
            continue
        start, end = tok.map
        header = cells(lines[start])
        for number in range(start + 2, end):
            found = cells(lines[number])
            if found > header:
                problems.append(
                    f"{name}:{number + 1}: table row has {found} cells and its "
                    f"header {header}; the excess is dropped, so the row "
                    "publishes cut short. A | inside a code span still splits "
                    "the cell: write \\|"
                )
    return problems


# --- diagrams ----------------------------------------------------------------


def diagram_digest(source: str) -> str:
    """The name a drawing of this block must carry: SHA-256 of the block's
    source bytes, exactly the lines between the fences."""
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


SVG_NS = "http://www.w3.org/2000/svg"
XHTML_NS = "http://www.w3.org/1999/xhtml"

#: What a drawing may contain: exactly what mermaid-cli wrote for the three
#: diagrams the manual has, and nothing else. An allowlist rather than a list
#: of dangers, because the dangers in an SVG are open-ended (animation that
#: rewrites an `href`, a stylesheet processing instruction, HTML inside a
#: `foreignObject`) and a list of them is complete only until the next one. A
#: new diagram type that needs another name is a reviewed change to this list,
#: as a registry entry is.
SVG_ELEMENTS = frozenset(
    [
        "svg",
        "g",
        "defs",
        "style",
        "path",
        "rect",
        "circle",
        "line",
        "polygon",
        "text",
        "tspan",
        "marker",
        "symbol",
        "filter",
        "feDropShadow",
        "linearGradient",
        "stop",
        "foreignObject",
    ]
)
#: HTML labels, allowed only inside a `foreignObject`.
XHTML_ELEMENTS = frozenset(["div", "span", "p", "i", "br"])
ATTRIBUTES = frozenset(
    [
        "alignment-baseline",
        "class",
        "clip-rule",
        "cx",
        "cy",
        "d",
        "dominant-baseline",
        "dx",
        "dy",
        "fill",
        "fill-rule",
        "filter",
        "flood-color",
        "flood-opacity",
        "font-family",
        "font-size",
        "gradientUnits",
        "height",
        "id",
        "marker-end",
        "marker-start",
        "markerHeight",
        "markerUnits",
        "markerWidth",
        "name",
        "offset",
        "orient",
        "points",
        "r",
        "refX",
        "refY",
        "role",
        "rx",
        "ry",
        "stdDeviation",
        "stop-color",
        "stop-opacity",
        "stroke",
        "stroke-dasharray",
        "stroke-width",
        "style",
        "text-anchor",
        "transform",
        "viewBox",
        "width",
        "x",
        "x1",
        "x2",
        "y",
        "y1",
        "y2",
    ]
)
#: Inert by definition: no browser acts on them.
ATTRIBUTE_PREFIXES = ("data-", "aria-")
#: In any value or text, whitespace and control characters removed and case
#: folded, so `Java\tScript :` reads as what a browser reads.
_FORBIDDEN = (
    "javascript:",
    "@import",
    "@font-face",
    "image-set(",
    "image(",
    "src(",
    "expression(",
)
_URL_REF = re.compile(r"url\(['\"]?(.)")


def _split(tag: str) -> tuple[str, str]:
    namespace, _, name = (
        tag[1:].partition("}") if tag.startswith("{") else ("", "", tag)
    )
    return namespace, name


def _value_problems(text: str) -> set[str]:
    folded = re.sub(r"[\s\x00-\x1f]", "", text).lower()
    # Checked after parsing, so `&#92;` counts as the backslash it becomes.
    # CSS reads `u\72l(` as `url(`, and no list of words survives escapes.
    if "\\" in folded:
        return {"a backslash, which CSS reads as an escape"}
    found = {
        f"a value that could run or fetch ({word})"
        for word in _FORBIDDEN
        if word in folded
    }
    for first in _URL_REF.findall(folded):
        if first != "#":
            found.add("a url(...) that is not a fragment of itself")
    return found


def svg_problems(path: Path, where: str) -> tuple[list[str], tuple[int, int]]:
    """Why this drawing may not be published, and its size from the viewBox.

    Opened directly from the site, an SVG runs with the site's origin and
    outside the page's CSP. The checks: the raw bytes hold no processing
    instruction, declaration, comment or CDATA section (`<?`, `<!`), which the
    XML parser would drop or expand before the tree below is read; every
    element and attribute is on the allowlists above, with HTML only inside
    a `foreignObject`; and no value or text, tails included, read after the
    parser has expanded character references, holds a backslash (a CSS
    escape), any word in `_FORBIDDEN`, or a `url(...)` that is not a fragment
    of the drawing itself. What this does not establish: that the drawing
    shows what its Mermaid block says, or that no future CSS function
    fetches without `url(`.
    """
    rel = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.name
    raw = path.read_bytes()
    found: set[str] = set()
    if b"<?" in raw or b"<!" in raw:
        found.add("a processing instruction, declaration, comment or CDATA (<? or <!)")
    if found:
        return [f"{where}: {rel} holds {reason}" for reason in sorted(found)], (0, 0)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return [f"{where}: {rel} is not well-formed XML: {exc}"], (0, 0)
    if _split(root.tag) != (SVG_NS, "svg"):
        return [f"{where}: {rel} is not an SVG document"], (0, 0)

    def walk(element: ET.Element, in_label: bool) -> None:
        namespace, name = _split(element.tag)
        if namespace == SVG_NS and name in SVG_ELEMENTS:
            in_label = in_label or name == "foreignObject"
        elif namespace == XHTML_NS and name in XHTML_ELEMENTS:
            if not in_label:
                found.add(f"an HTML element outside a foreignObject ({name})")
        else:
            found.add(f"an element this builder does not publish ({name})")
        for key, value in element.attrib.items():
            # A namespaced attribute (`xlink:href`) arrives as `{ns}name`,
            # which is never a bare name on the list, so it is refused here.
            if not (key in ATTRIBUTES or key.startswith(ATTRIBUTE_PREFIXES)):
                found.add(
                    f"an attribute this builder does not publish ({_split(key)[1]})"
                )
            found.update(_value_problems(value))
        found.update(_value_problems(element.text or ""))
        found.update(_value_problems(element.tail or ""))
        for child in element:
            walk(child, in_label)

    walk(root, False)
    problems = [f"{where}: {rel} holds {reason}" for reason in sorted(found)]
    box = _VIEWBOX.fullmatch(root.get("viewBox") or "")
    if box is None:
        problems.append(f"{where}: {rel} has no viewBox to size the image from")
        return problems, (0, 0)
    return problems, (round(float(box.group(1))), round(float(box.group(2))))


# --- rendering rules ---------------------------------------------------------
# Signature fixed by markdown-it: (renderer, tokens, idx, options, env).


def _heading_open(_r: Any, tokens: list[Token], idx: int, _o: Any, _e: Any) -> str:
    tok = tokens[idx]
    anchor = html.escape(str(tok.meta["anchor"]))
    return f'<{tok.tag} id="{anchor}"><a class="self" href="#{anchor}">'


def _heading_close(_r: Any, tokens: list[Token], idx: int, _o: Any, _e: Any) -> str:
    return f"</a></{tokens[idx].tag}>\n"


def _table_open(_r: Any, _t: list[Token], _i: int, _o: Any, _e: Any) -> str:
    # Focusable so a keyboard can scroll a table wider than the column.
    return '<div class="table-wrap" tabindex="0">\n<table>\n'


def _table_close(_r: Any, _t: list[Token], _i: int, _o: Any, _e: Any) -> str:
    return "</table>\n</div>\n"


def _code(_r: Any, tokens: list[Token], idx: int, _o: Any, _e: Any) -> str:
    tok = tokens[idx]
    source = escapeHtml(tok.content)
    diagram = tok.meta.get("diagram")
    if not isinstance(diagram, Diagram):
        return f'<pre tabindex="0"><code>{source}</code></pre>\n'
    src = f"diagrams/{diagram.name}"
    return (
        '<figure class="diagram">\n'
        f'<a class="diagram-art" href="{src}">'
        f'<img src="{src}" width="{diagram.width}" height="{diagram.height}" '
        f'alt="{html.escape(str(tok.meta["alt"]))}"></a>\n'
        "<details>\n<summary>Mermaid source</summary>\n"
        f'<pre tabindex="0"><code>{source}</code></pre>\n'
        "</details>\n</figure>\n"
    )


def _code_inline(_r: Any, tokens: list[Token], idx: int, _o: Any, _e: Any) -> str:
    # A break opportunity after `_` and `/`, so a long identifier in a narrow
    # table column wraps where a reader expects rather than mid-word. `<wbr>`
    # adds no character: a copied identifier is the identifier.
    text = escapeHtml(tokens[idx].content)
    return "<code>" + re.sub(r"([_/])", r"\1<wbr>", text) + "</code>"


def markdown() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False}).enable("table")
    md.add_render_rule("heading_open", _heading_open)
    md.add_render_rule("heading_close", _heading_close)
    md.add_render_rule("table_open", _table_open)
    md.add_render_rule("table_close", _table_close)
    md.add_render_rule("fence", _code)
    md.add_render_rule("code_block", _code)
    md.add_render_rule("code_inline", _code_inline)
    return md


# --- the page ----------------------------------------------------------------


class Builder:
    """One document into one page. Collects problems; never stops at the first."""

    def __init__(
        self,
        *,
        name: str,
        repository: str,
        ref: str,
        root: Path = ROOT,
        diagrams: Path = DIAGRAMS,
    ) -> None:
        self.name = name
        self.base = posixpath.dirname(name)
        self.repository = repository
        self.ref = ref
        self.root = root
        self.diagrams = diagrams
        self.problems: list[str] = []
        self.fragments: list[tuple[str, str]] = []

    def url(self, path: str, *, tree: bool = False) -> str:
        kind = "tree" if tree else "blob"
        ref = quote(self.ref)
        return f"https://github.com/{self.repository}/{kind}/{ref}/{quote(path)}"

    def resolve(self, href: str, where: str) -> str:
        """The href to publish. A problem is recorded rather than raised, and
        the original href is returned so rendering can go on to the next one."""
        if href.startswith("#"):
            self.fragments.append((unquote(href[1:]), where))
            return href
        if href.startswith("//") or _SCHEME.match(href):
            if href.lower().startswith("https://"):
                return href
            self.problems.append(
                f"{where}: link is neither https: nor in the repository: {href}"
            )
            return href
        parts = urlsplit(href)
        target = posixpath.normpath(posixpath.join(self.base, unquote(parts.path)))
        if parts.query or target == ".." or target.startswith(("../", "/")):
            self.problems.append(
                f"{where}: link does not name a path in the repository: {href}"
            )
            return href
        path = self.root / target
        if not path.exists():
            self.problems.append(f"{where}: link to {target}, which is not in the tree")
            return href
        fragment = f"#{parts.fragment}" if parts.fragment else ""
        return self.url(target, tree=path.is_dir()) + fragment

    def diagram(self, tok: Token, where: str, section: str) -> Diagram | None:
        digest = diagram_digest(tok.content)
        path = self.diagrams / f"{digest}.svg"
        if not path.is_file():
            self.problems.append(
                f"{where}: diagram has no drawing; draw it into "
                f"docs/site/diagrams/{digest}.svg (tools/build_site.py says how)"
            )
            return None
        problems, (width, height) = svg_problems(path, where)
        self.problems.extend(problems)
        if problems:
            return None
        tok.meta["alt"] = (
            f"Diagram for {section}. Its Mermaid source follows."
            if section
            else "Diagram. Its Mermaid source follows."
        )
        return Diagram(digest, width, height)

    def build(self, text: str) -> Page:
        md = markdown()
        renderer = md.renderer
        if not isinstance(renderer, RendererHTML):
            raise TypeError("markdown-it is not configured with its HTML renderer")
        tokens = md.parse(text)
        self.problems.extend(table_problems(tokens, text.splitlines(), self.name))

        slugger = Slugger()
        anchors: set[str] = set()
        toc: list[Heading] = []
        diagrams: list[Diagram] = []
        title = title_html = section = ""
        body: list[Token] = []
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            where = f"{self.name}:{tok.map[0] + 1}" if tok.map else self.name
            if tok.type == "heading_open":
                children = tokens[i + 1].children or []
                if any(child.type == "link_open" for child in children):
                    self.problems.append(
                        f"{where}: a heading holds a link; it is one already"
                    )
                if tok.tag == "h1" and not title:
                    title = plain(children)
                    title_html = renderer.renderInline(children, md.options, {})
                    i += 3
                    continue
                section = plain(children)
                anchor = slugger(section)
                if not anchor:
                    self.problems.append(
                        f"{where}: heading has no text to make an anchor from"
                    )
                anchors.add(anchor)
                tok.meta["anchor"] = anchor
                tokens[i + 2].meta["anchor"] = anchor
                # The manual's own contents list is on the page; the nav is
                # a contents list, so it does not list one.
                if tok.tag in ("h2", "h3") and anchor != "contents":
                    rendered = renderer.renderInline(children, md.options, {})
                    toc.append(Heading(int(tok.tag[1]), anchor, rendered))
            elif tok.type == "fence" and tok.info.strip().lower() == "mermaid":
                drawn = self.diagram(tok, where, section)
                if drawn is not None:
                    tok.meta["diagram"] = drawn
                    diagrams.append(drawn)
            elif tok.type == "inline":
                for child in tok.children or []:
                    if child.type == "link_open":
                        href = str(child.attrGet("href") or "")
                        child.attrSet("href", self.resolve(href, where))
                    elif child.type == "image":
                        src = child.attrGet("src")
                        self.problems.append(
                            f"{where}: images are not published by this builder: {src}"
                        )
            body.append(tok)
            i += 1

        if not title:
            self.problems.append(f"{self.name}: no level-one heading to title the page")
        for fragment, where in self.fragments:
            if fragment not in anchors:
                self.problems.append(
                    f"{where}: link to #{fragment}, which no heading has"
                )
        if self.problems:
            raise SiteError(self.problems)
        return Page(
            title, title_html, renderer.render(body, md.options, {}), toc, diagrams
        )


def toc_html(entries: Sequence[Heading]) -> str:
    """Level-two headings with their level-three headings nested under them."""
    out = ["<ul>"]
    in_item = in_sub = False
    for h in entries:
        link = f'<a href="#{html.escape(h.anchor)}">{h.html}</a>'
        if h.level == 2 or not in_item:
            if in_sub:
                out.append("</ul>")
                in_sub = False
            if in_item:
                out.append("</li>")
            out.append(f"<li>{link}")
            in_item = True
        else:
            if not in_sub:
                out.append("<ul>")
                in_sub = True
            out.append(f"<li>{link}</li>")
    if in_sub:
        out.append("</ul>")
    if in_item:
        out.append("</li>")
    out.append("</ul>")
    return "\n".join(out)


def image_size(path: Path) -> tuple[int, int]:
    """Width and height from a GIF or PNG header. The page reserves the
    banner's space before it loads, and the gate compares the still with the
    animation, without an imaging library."""
    head = path.read_bytes()[:24]
    if head[:6] in (b"GIF87a", b"GIF89a"):
        width, height = struct.unpack("<HH", head[6:10])
    elif head[:8] == b"\x89PNG\r\n\x1a\n":
        width, height = struct.unpack(">II", head[16:24])
    else:
        raise ValueError(f"{path.name} is neither a GIF nor a PNG")
    return int(width), int(height)


def project() -> tuple[str, str, str]:
    meta = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    return str(meta["name"]), str(meta["version"]), str(meta["description"])


def build(
    text: str,
    *,
    name: str = "docs/MANUAL.md",
    repository: str = REPOSITORY,
    ref: str = "main",
    root: Path = ROOT,
    diagrams: Path = DIAGRAMS,
) -> tuple[str, Page]:
    """The full page for one document and what it was built from, or
    SiteError with every problem in it."""
    builder = Builder(
        name=name, repository=repository, ref=ref, root=root, diagrams=diagrams
    )
    page = builder.build(text)
    package, version, description = project()
    repo_url = f"https://github.com/{repository}"
    if _SHA.fullmatch(ref):
        at = f'commit <a href="{repo_url}/commit/{ref}"><code>{ref[:7]}</code></a>'
    else:
        tree = builder.url("", tree=True)
        at = f'<a href="{tree}"><code>{html.escape(ref)}</code></a>'
    source = builder.url(name)
    tool = builder.url("tools/build_site.py")
    width, height = image_size(BANNER)
    title = (
        page.title if page.title.startswith(CODENAME) else f"{CODENAME}: {page.title}"
    )
    template = string.Template(TEMPLATE.read_text(encoding="utf-8"))
    rendered = template.substitute(
        title=html.escape(title),
        description=html.escape(description),
        codename=CODENAME,
        banner=BANNER.name,
        banner_still=BANNER_STILL.name,
        banner_width=width,
        banner_height=height,
        heading=page.title_html,
        provenance=(
            f'<a href="{repo_url}">{html.escape(package)}</a> '
            f"{html.escape(version)}, rendered from {at}."
        ),
        toc=toc_html(page.toc),
        body=page.body,
        footer=(
            f'Generated from <a href="{source}"><code>{html.escape(name)}</code></a> '
            f'by <a href="{tool}"><code>tools/build_site.py</code></a>. The file in '
            "the repository is the source; this page is a copy, rebuilt when the "
            "file or the builder changes."
        ),
    )
    return rendered, page


def render(text: str, **kwargs: Any) -> str:
    """The full page for one document, or SiteError with every problem in it."""
    return build(text, **kwargs)[0]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render docs/MANUAL.md as a static site.")
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("_site"),
        help="directory to write the page and its files into (default: _site)",
    )
    ap.add_argument(
        "--ref",
        default="main",
        help="commit or branch the page's repository links point at (default: main)",
    )
    ap.add_argument(
        "--repository",
        default=REPOSITORY,
        help=f"owner/name on GitHub (default: {REPOSITORY})",
    )
    args = ap.parse_args(argv)

    if not _REF.fullmatch(args.ref) or ".." in args.ref:
        print(f"--ref is not a commit or branch name: {args.ref!r}", file=sys.stderr)
        return 2
    if not _REPO.fullmatch(args.repository):
        print(f"--repository is not owner/name: {args.repository!r}", file=sys.stderr)
        return 2

    name = SOURCE.relative_to(ROOT).as_posix()
    try:
        text, page = build(
            SOURCE.read_text(encoding="utf-8"),
            name=name,
            repository=args.repository,
            ref=args.ref,
        )
    except SiteError as exc:
        print(
            f"{name}: not published, {len(exc.problems)} problem(s):", file=sys.stderr
        )
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    except (OSError, KeyError, ValueError) as exc:
        print(f"the site sources could not be read: {exc}", file=sys.stderr)
        return 2

    try:
        (args.out / "diagrams").mkdir(parents=True, exist_ok=True)
        (args.out / "index.html").write_text(text, encoding="utf-8")
        for asset in (STYLESHEET, BANNER, BANNER_STILL):
            shutil.copyfile(asset, args.out / asset.name)
        for diagram in page.diagrams:
            shutil.copyfile(
                DIAGRAMS / diagram.name, args.out / "diagrams" / diagram.name
            )
    except OSError as exc:
        print(f"the site could not be written: {exc}", file=sys.stderr)
        return 2
    print(f"built {args.out / 'index.html'} from {name} at {args.ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
