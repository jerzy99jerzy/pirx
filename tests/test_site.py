"""The site is the manual, rendered.

`tools/build_site.py` builds the real `docs/MANUAL.md` here, so an edit that
would publish broken fails the gate before it reaches `main`; each refusal the
builder makes is pinned with a document written to trigger it. Ported from
cve-digest's `tests/test_site.py`, with the diagram checks that repository's
manual has no use for.

The builder is loaded by path rather than imported, so the suite does not
depend on the directory pytest was started from.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pirx_build_site", ROOT / "tools" / "build_site.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


build_site = _load()

SHA = "0123456789abcdef0123456789abcdef01234567"
REPO = f"https://github.com/{build_site.REPOSITORY}"
MERMAID = re.compile(r"^```mermaid\n(.*?)^```", re.M | re.S)


class Collect(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.srcs: list[str] = []
        self.srcsets: list[str] = []
        self.alts: list[str | None] = []
        self.links: list[dict[str, str | None]] = []
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        self.tags.append(tag)
        if attr.get("id"):
            self.ids.add(str(attr["id"]))
        if attr.get("src"):
            self.srcs.append(str(attr["src"]))
        if attr.get("srcset"):
            self.srcsets.append(str(attr["srcset"]))
        if tag == "img":
            self.alts.append(attr.get("alt"))
        if tag == "a" and attr.get("href"):
            self.hrefs.append(str(attr["href"]))
        if tag == "link":
            self.links.append(attr)


@pytest.fixture(scope="module")
def page() -> str:
    return str(
        build_site.render(build_site.SOURCE.read_text(encoding="utf-8"), ref=SHA)
    )


def parse(text: str) -> Collect:
    collect = Collect()
    collect.feed(text)
    return collect


def refusal(text: str, **kwargs: object) -> list[str]:
    with pytest.raises(build_site.SiteError) as caught:
        build_site.render(text, ref=SHA, **kwargs)
    return list(caught.value.problems)


def blocks() -> list[str]:
    return MERMAID.findall(build_site.SOURCE.read_text(encoding="utf-8"))


# --- the real manual ---------------------------------------------------------


def test_every_fragment_on_the_page_names_an_anchor_on_the_page(page: str) -> None:
    seen = parse(page)
    fragments = [h[1:] for h in seen.hrefs if h.startswith("#")]
    assert fragments, "the contents and the headings link to anchors"
    assert [f for f in fragments if unquote(f) not in seen.ids] == []


def test_the_manuals_own_contents_list_resolves_on_the_page(page: str) -> None:
    """MANUAL.md carries a hand-written contents list of `#` links. Each must
    land on a heading here as it does on GitHub."""
    text = build_site.SOURCE.read_text(encoding="utf-8")
    listed = re.findall(r"^\d+\. \[[^\]]+\]\(#([^)]+)\)", text, re.M)
    assert len(listed) == len(re.findall(r"^## \d+\. ", text, re.M))
    assert [f for f in listed if f not in parse(page).ids] == []


def test_no_link_is_left_relative_to_a_site_that_has_one_page(page: str) -> None:
    """A relative link that works on GitHub is a 404 on the site. The one
    relative target allowed is a diagram's own drawing, which is published."""
    assert [
        h
        for h in parse(page).hrefs
        if not (
            h.startswith(("#", "https://"))
            or re.fullmatch(r"diagrams/[0-9a-f]{64}\.svg", h)
        )
    ] == []


def test_repository_links_are_pinned_to_the_built_commit_and_exist(page: str) -> None:
    pinned = re.compile(re.escape(REPO) + r"/(blob|tree)/([^/]+)/([^#]*)")
    links = [m for m in (pinned.match(h) for h in parse(page).hrefs) if m]
    targets = {unquote(m.group(3)) for m in links}
    assert {"docs/MANUAL.md", "tools/build_site.py"} <= targets
    assert {m.group(2) for m in links} == {SHA}
    assert [t for t in targets if t and not (ROOT / t).exists()] == []


def test_the_page_runs_no_script_and_loads_nothing_from_elsewhere(page: str) -> None:
    seen = parse(page)
    assert "script" not in seen.tags
    diagrams = [f"diagrams/{build_site.diagram_digest(b)}.svg" for b in blocks()]
    assert seen.srcs == [build_site.BANNER.name, *diagrams]
    assert seen.srcsets == [build_site.BANNER_STILL.name]
    assert seen.links == [{"rel": "stylesheet", "href": "site.css"}]
    assert "default-src 'none'; style-src 'self'; img-src 'self'" in page


def test_the_header_carries_the_readme_banner_and_the_codename(page: str) -> None:
    """The page and the README show the same file, so a new banner reaches
    both or neither."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    first_image = re.search(r"!\[[^\]]*\]\(([^)]+)\)", readme)
    assert first_image is not None
    assert first_image.group(1) == build_site.BANNER.relative_to(ROOT).as_posix()
    assert parse(page).alts[0] == "Pirx, remediation agent"
    assert (
        '<source srcset="pirx-banner-still.png" '
        'media="(prefers-reduced-motion: reduce)">'
    ) in page


def test_the_still_frame_is_the_size_of_the_banner(page: str) -> None:
    """The still is exported by hand from the GIF's first frame. A banner
    replaced without a new still would show a stale or misshapen header to
    readers who asked for reduced motion."""
    assert build_site.BANNER_STILL.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    size = build_site.image_size(build_site.BANNER)
    assert build_site.image_size(build_site.BANNER_STILL) == size
    assert f'width="{size[0]}" height="{size[1]}"' in page


def test_image_size_refuses_a_file_it_cannot_read(tmp_path: Path) -> None:
    other = tmp_path / "x.jpg"
    other.write_bytes(b"\xff\xd8\xff\xe0" + b"\0" * 20)
    with pytest.raises(ValueError, match="neither a GIF nor a PNG"):
        build_site.image_size(other)


def test_every_section_of_the_manual_is_in_the_contents_but_the_contents(
    page: str,
) -> None:
    text = build_site.SOURCE.read_text(encoding="utf-8")
    built = build_site.Builder(
        name="docs/MANUAL.md", repository=build_site.REPOSITORY, ref=SHA
    ).build(text)
    headings = [h for h in re.findall(r'<h[23] id="([^"]+)">', page) if h != "contents"]
    assert [h.anchor for h in built.toc] == headings
    assert len(headings) == len(re.findall(r"^#{2,3} ", text, re.M)) - 1
    assert '<h2 id="contents">' in page


def test_the_title_and_description(page: str) -> None:
    _, _, description = build_site.project()
    assert "<title>Pirx manual</title>" in page
    assert f'name="description" content="{description}"' in page


def test_the_build_is_deterministic(tmp_path: Path) -> None:
    """Two builds in two processes with different hash seeds, so an ordering
    that depends on set or dict iteration would show."""
    import os
    import subprocess

    pages = []
    for seed in ("1", "2"):
        out = tmp_path / seed
        env = {**os.environ, "PYTHONHASHSEED": seed}
        subprocess.run(
            [sys.executable, "-m", "tools.build_site", "--out", str(out), "--ref", SHA],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
        )
        pages.append((out / "index.html").read_bytes())
    assert pages[0] == pages[1]


# --- diagrams ----------------------------------------------------------------


def test_every_diagram_in_the_manual_is_published_as_its_drawing(page: str) -> None:
    found = blocks()
    assert len(found) == 3, "the manual's diagrams: 3.1, 3.2 and 8.3"
    for source in found:
        digest = build_site.diagram_digest(source)
        assert f'<img src="diagrams/{digest}.svg"' in page
    assert page.count('<figure class="diagram">') == len(found)
    assert page.count("<summary>Mermaid source</summary>") == len(found)


def test_no_drawing_is_left_behind_by_a_redrawn_diagram() -> None:
    """A drawing no block names is a picture of a diagram that no longer
    exists; it would sit in the tree looking current."""
    named = {f"{build_site.diagram_digest(b)}.svg" for b in blocks()}
    present = {p.name for p in build_site.DIAGRAMS.iterdir()}
    assert present == named


def test_every_drawing_passes_the_checks_it_is_published_under() -> None:
    for path in sorted(build_site.DIAGRAMS.glob("*.svg")):
        problems, (width, height) = build_site.svg_problems(path, "test")
        assert problems == [], path.name
        assert width > 0 and height > 0


def test_an_edited_diagram_without_a_new_drawing_is_refused() -> None:
    text = build_site.SOURCE.read_text(encoding="utf-8")
    edited = text.replace("participant D as downstream", "participant D as server", 1)
    assert edited != text
    fence = [m.start() for m in re.finditer(r"^```mermaid$", edited, re.M)][2]
    line = edited.count("\n", 0, fence) + 1
    problems = refusal(edited)
    assert len(problems) == 1
    assert problems[0].startswith(f"docs/MANUAL.md:{line}: diagram has no drawing")
    digest = build_site.diagram_digest(MERMAID.findall(edited)[2])
    assert f"docs/site/diagrams/{digest}.svg" in problems[0]


SVG = 'xmlns="http://www.w3.org/2000/svg"'
XHTML = "xmlns='http://www.w3.org/1999/xhtml'"
SAFE = (
    f'<svg {SVG} viewBox="0 0 120 40">'
    "<defs><marker id='m'/></defs><style>.a{fill:#fff}</style>"
    "<path marker-end='url(#m)'/>{}</svg>"
)
EXAMPLE = "https://example.com/x"


def drawn(tmp_path: Path, drawing: str) -> list[str]:
    source = "flowchart LR\n    A --> B\n"
    (tmp_path / f"{build_site.diagram_digest(source)}.svg").write_text(drawing)
    return refusal(f"# T\n\n## S\n\n```mermaid\n{source}```\n", diagrams=tmp_path)


@pytest.mark.parametrize(
    ("drawing", "reason"),
    [
        (SAFE.replace("{}", "<script>alert(1)</script>"), "(script)"),
        (
            SAFE.replace("{}", "<rect onload='x()'/>"),
            "attribute this builder does not publish (onload)",
        ),
        (SAFE.replace("{}", "<rect class='java&#9;Script :x'/>"), "(javascript:)"),
        (SAFE.replace("{}", f"<image href='{EXAMPLE}'/>"), "(image)"),
        (
            SAFE.replace(
                "{}",
                f"<g xmlns:xl='http://www.w3.org/1999/xlink' xl:href='{EXAMPLE}'/>",
            ),
            "attribute this builder does not publish (href)",
        ),
        (
            SAFE.replace("{}", f"<set attributeName='href' to='{EXAMPLE}'/>"),
            "(set)",
        ),
        (
            SAFE.replace(
                "{}", f"<animate attributeName='href' values='#a;{EXAMPLE}'/>"
            ),
            "(animate)",
        ),
        (
            SAFE.replace(
                "{}",
                f"<foreignObject><object {XHTML} data='{EXAMPLE}'/></foreignObject>",
            ),
            "(object)",
        ),
        (
            SAFE.replace(
                "{}",
                f"<foreignObject><img {XHTML} srcset='{EXAMPLE}'/></foreignObject>",
            ),
            "(img)",
        ),
        (
            SAFE.replace(
                "{}",
                f"<foreignObject><meta {XHTML} http-equiv='refresh' "
                f"content='0;url={EXAMPLE}'/></foreignObject>",
            ),
            "(meta)",
        ),
        (
            SAFE.replace("{}", f"<div {XHTML}>x</div>"),
            "HTML element outside a foreignObject (div)",
        ),
        (
            f'<?xml-stylesheet href="{EXAMPLE}"?>' + SAFE.replace("{}", ""),
            "(<? or <!)",
        ),
        (
            "<!DOCTYPE svg [<!ENTITY e 'x'>]>" + SAFE.replace("{}", ""),
            "(<? or <!)",
        ),
        (SAFE.replace("{}", "<!-- hidden -->"), "(<? or <!)"),
        (SAFE.replace("{}", "<style>.a{background:u\\72l(x)}</style>"), "a backslash"),
        (
            SAFE.replace(
                "{}", f"<style>.a{{background:image-set('{EXAMPLE}' 1x)}}</style>"
            ),
            "(image-set()",
        ),
        (
            SAFE.replace("{}", "<style>.a{fill:#000}</style><g/>@import 'x.css';"),
            "(@import)",
        ),
        (
            SAFE.replace("{}", "<style>@font-face{src:local(x)}</style>"),
            "(@font-face)",
        ),
        (
            SAFE.replace("{}", f"<rect style='fill:url( \"{EXAMPLE}\")'/>"),
            "url(...) that is not a fragment",
        ),
        (
            SAFE.replace("{}", f"<style>rect{{fill:u&#92;72l({EXAMPLE})}}</style>"),
            "a backslash",
        ),
        (
            SAFE.replace("{}", f"<rect style='fill:u&#x5c;72l({EXAMPLE})'/>"),
            "a backslash",
        ),
        (
            SAFE.replace(
                "{}",
                f"<foreignObject><div {XHTML} style='background:u&#92;72l({EXAMPLE})'>"
                "x</div></foreignObject>",
            ),
            "a backslash",
        ),
        (SAFE.replace("{}", "<rect style='width:expression(x())'/>"), "(expression()"),
        (
            SAFE.replace("{}", f"<style>.a{{background:src('{EXAMPLE}')}}</style>"),
            "(src()",
        ),
        (
            SAFE.replace("{}", f"<style>.a{{background:image('{EXAMPLE}')}}</style>"),
            "(image()",
        ),
        (
            SAFE.replace("{}", "<x:path xmlns:x='urn:x'/>"),
            "element this builder does not publish (path)",
        ),
    ],
    ids=[
        "script",
        "handler",
        "javascript-folded",
        "image",
        "xlink-href",
        "set-href",
        "animate-href",
        "object",
        "img-srcset",
        "meta-refresh",
        "html-outside-label",
        "stylesheet-pi",
        "doctype",
        "comment",
        "css-escape",
        "image-set",
        "import-in-tail",
        "font-face",
        "url",
        "charref-backslash-style",
        "charref-hex-backslash-attribute",
        "charref-backslash-html-label",
        "expression",
        "css-src",
        "css-image",
        "foreign-namespace-element",
    ],
)
def test_a_drawing_outside_the_allowlist_or_able_to_fetch_is_refused(
    tmp_path: Path, drawing: str, reason: str
) -> None:
    """Each case is one the denylist this check replaced let through, or one
    it already caught. None is opened in a browser here: the refusal is the
    claim, not what a browser would have done."""
    problems = drawn(tmp_path, drawing)
    assert any(reason in problem for problem in problems), problems


def test_mermaids_own_shape_is_admitted(tmp_path: Path) -> None:
    """Fragment references, a stylesheet and an HTML label inside a
    foreignObject are what mmdc writes; the checks refuse what a hand edit
    could add, not those."""
    source = "flowchart LR\n    A --> B\n"
    drawing = SAFE.replace(
        "{}",
        f"<foreignObject><div {XHTML}><span class='l'><p><i>x</i><br/></p></span>"
        "</div></foreignObject><g data-id='n' aria-hidden='true' filter='url(#m)'/>",
    )
    (tmp_path / f"{build_site.diagram_digest(source)}.svg").write_text(drawing)
    out = build_site.render(
        f"# T\n\n## Section\n\n```mermaid\n{source}```\n", ref=SHA, diagrams=tmp_path
    )
    assert 'width="120" height="40"' in out
    assert 'alt="Diagram for Section. Its Mermaid source follows."' in out


def test_the_allowlists_are_exactly_what_the_drawings_use() -> None:
    """A name on a list that no drawing uses is a door nobody reviewed for a
    reason; a name a drawing uses and the list lacks fails the build. Either
    way the list moves with a reviewed change."""
    import xml.etree.ElementTree as ET

    elements: set[str] = set()
    attributes: set[str] = set()
    for path in build_site.DIAGRAMS.glob("*.svg"):
        for element in ET.fromstring(path.read_bytes()).iter():
            elements.add(element.tag.rsplit("}", 1)[-1])
            attributes |= {
                k
                for k in element.attrib
                if not k.startswith(build_site.ATTRIBUTE_PREFIXES)
            }
    assert elements == build_site.SVG_ELEMENTS | build_site.XHTML_ELEMENTS
    assert attributes == build_site.ATTRIBUTES


def test_a_drawing_that_is_not_an_svg_is_refused(tmp_path: Path) -> None:
    source = "flowchart LR\n    A --> B\n"
    path = tmp_path / f"{build_site.diagram_digest(source)}.svg"
    doc = f"# T\n\n```mermaid\n{source}```\n"
    path.write_text("<svg")
    assert "is not well-formed XML" in refusal(doc, diagrams=tmp_path)[0]
    path.write_text("<html/>")
    assert "is not an SVG document" in refusal(doc, diagrams=tmp_path)[0]
    path.write_text(f"<svg {XHTML} viewBox='0 0 1 1'/>")
    assert "is not an SVG document" in refusal(doc, diagrams=tmp_path)[0]
    path.write_text(f"<svg {SVG}/>")
    assert "has no viewBox" in refusal(doc, diagrams=tmp_path)[0]


# --- what the builder refuses ------------------------------------------------


def test_anchors_follow_githubs_rule() -> None:
    """The rule github-slugger applies, so a fragment copied from the file on
    GitHub opens the same section here."""
    assert build_site.slug("1. What Pirx does") == "1-what-pirx-does"
    assert build_site.slug("3.1 Single process (the runner)") == (
        "31-single-process-the-runner"
    )
    assert build_site.slug("15. Reference: exit codes and environment") == (
        "15-reference-exit-codes-and-environment"
    )
    slugger = build_site.Slugger()
    assert [slugger("Linux"), slugger("Linux"), slugger("Linux")] == [
        "linux",
        "linux-1",
        "linux-2",
    ]


def test_raw_html_in_the_source_is_escaped_not_rendered() -> None:
    out = build_site.render(
        "# T\n\n<script>alert(1)</script>\n\nok <b>bold</b>\n", ref=SHA
    )
    body = out.split('<main id="manual"', 1)[1]
    assert "<script" not in body and "<b>" not in body
    assert "&lt;script&gt;" in body


def test_a_pipe_inside_a_code_span_in_a_table_is_refused() -> None:
    table = "# T\n\n| a | b |\n| --- | --- |\n| `x` | piped (`{}`) |\n"
    problems = refusal(table.format("| head"))
    assert len(problems) == 1
    assert problems[0].startswith("docs/MANUAL.md:5: table row has 3 cells")
    assert "write \\|" in problems[0]
    assert "piped (<code>| head</code>)" in build_site.render(
        table.format("\\| head"), ref=SHA
    )


def test_the_remaining_refusals_each_fire() -> None:
    """Refusals the joint test above does not reach: a query string, a
    protocol-relative link, a heading with no text, and no title."""
    assert (
        "does not name a path in the repository: THESIS.md?x=1"
        in refusal("# T\n\n[q](THESIS.md?x=1)\n")[0]
    )
    assert (
        "neither https: nor in the repository: //example.com/x"
        in refusal("# T\n\n[p](//example.com/x)\n")[0]
    )
    assert "heading has no text to make an anchor from" in refusal("# T\n\n## !!\n")[0]
    assert "no level-one heading to title the page" in refusal("## Only\n")[0]


def test_links_that_would_publish_broken_are_refused_together() -> None:
    problems = refusal(
        "# T\n\n## Section\n\n"
        "[a](missing.md) [b](http://example.com) [c](#nowhere) "
        "[d](../../outside.md)\n\n"
        "![e](assets/pirx-banner.gif)\n\n"
        "## [linked](THESIS.md)\n"
    )
    joined = "\n".join(problems)
    assert len(problems) == 6
    assert "link to docs/missing.md, which is not in the tree" in joined
    assert "neither https: nor in the repository: http://example.com" in joined
    assert "link to #nowhere, which no heading has" in joined
    assert "does not name a path in the repository: ../../outside.md" in joined
    assert "images are not published" in joined
    assert "a heading holds a link" in joined


# --- the command -------------------------------------------------------------


def test_the_cli_writes_the_page_and_everything_it_names(tmp_path: Path) -> None:
    out = tmp_path / "site"
    assert build_site.main(["--out", str(out), "--ref", SHA]) == 0
    written = sorted(
        p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()
    )
    diagrams = [f"diagrams/{build_site.diagram_digest(b)}.svg" for b in blocks()]
    assert written == sorted(
        ["index.html", "site.css", build_site.BANNER.name, build_site.BANNER_STILL.name]
        + diagrams
    )
    for source in (build_site.STYLESHEET, build_site.BANNER, build_site.BANNER_STILL):
        assert (out / source.name).read_bytes() == source.read_bytes()
    for name in diagrams:
        assert (out / name).read_bytes() == (build_site.SITE / name).read_bytes()
    _, version, _ = build_site.project()
    assert f"</a> {version}, rendered from commit" in (out / "index.html").read_text()


def test_the_cli_refuses_a_ref_or_repository_it_would_have_to_trust(
    tmp_path: Path,
) -> None:
    out = tmp_path / "site"
    assert build_site.main(["--out", str(out), "--ref", '"><b>x']) == 2
    assert build_site.main(["--out", str(out), "--ref", "a/../b"]) == 2
    assert build_site.main(["--out", str(out), "--repository", "no-slash"]) == 2
    assert not out.exists()


def github_glob(pattern: str) -> re.Pattern[str]:
    """A workflow path filter as GitHub reads it: `*` stops at `/`, `**`
    crosses it, `?` is one character that is not `/`. fnmatch lets `*` cross
    `/`, which would pass a filter GitHub never fires on."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def test_github_glob_reads_a_filter_as_github_does() -> None:
    assert github_glob("docs/site/**").fullmatch("docs/site/diagrams/a.svg")
    assert not github_glob("docs/site/*").fullmatch("docs/site/diagrams/a.svg")
    assert github_glob("docs/site/*").fullmatch("docs/site/site.css")


def test_every_file_the_page_is_built_from_republishes_it() -> None:
    """pages.yml rebuilds on a push that touches one of its paths. A source the
    builder reads that is missing from that list changes the page only when
    something else happens to change too. pyproject.toml is left out on
    purpose: a version bump alone does not republish, which MERGE-PROCEDURE.md
    states."""
    workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text()
    block = re.search(r"\n    paths:\n((?:      - .+\n)+)", workflow)
    assert block is not None, "no push paths in pages.yml"
    patterns = [line.split("- ", 1)[1].strip() for line in block.group(1).splitlines()]
    inputs = [
        build_site.SOURCE,
        build_site.TEMPLATE,
        build_site.STYLESHEET,
        build_site.BANNER,
        build_site.BANNER_STILL,
        *sorted(build_site.DIAGRAMS.glob("*.svg")),
        ROOT / "tools" / "build_site.py",
        ROOT / "requirements-docs.txt",
    ]
    rels = [p.relative_to(ROOT).as_posix() for p in inputs]
    assert [
        r for r in rels if not any(github_glob(pat).fullmatch(r) for pat in patterns)
    ] == []


# --- the stylesheet ----------------------------------------------------------


def _palette(css: str, dark: bool) -> dict[str, str]:
    root = re.search(r":root\s*\{(.*?)\}", css, re.S)
    assert root is not None
    tokens = dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-f]{6})", root.group(1)))
    if dark:
        block = re.search(
            r"prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{(.*?)\}", css, re.S
        )
        assert block is not None
        tokens.update(re.findall(r"--([a-z-]+):\s*(#[0-9a-f]{6})", block.group(1)))
    return tokens


def _contrast(a: str, b: str) -> float:
    def luminance(colour: str) -> float:
        channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        r, g, b = (
            c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
            for c in channels
        )
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


@pytest.mark.parametrize("dark", [False, True], ids=["light", "dark"])
def test_every_text_colour_clears_wcag_aa_on_its_background(dark: bool) -> None:
    """The stylesheet says so in its header; this is what makes it true."""
    tokens = _palette(build_site.STYLESHEET.read_text(encoding="utf-8"), dark)
    pairs = [
        ("ink", "paper"),
        ("muted", "paper"),
        ("link", "paper"),
        ("ink", "code"),
        ("link", "code"),
        ("band-ink", "band"),
        ("band-muted", "band"),
        ("signal", "band"),
    ]
    ratios = {
        f"{fg}/{bg}": round(_contrast(tokens[fg], tokens[bg]), 2) for fg, bg in pairs
    }
    assert {k: v for k, v in ratios.items() if v < 4.5} == {}


def test_the_band_is_the_banners_own_edge_colour() -> None:
    """The banner sits on the band without a seam only if the two match. A
    tripwire, not a proof: it reads the GIF's global colour table and asserts
    the band's colour is one the banner is drawn with. That it is the edge
    colour was read with Pillow once (0.7.6.2 review) and is not re-read here,
    because decoding the frame would need an imaging library."""
    gif = build_site.BANNER.read_bytes()
    packed = gif[10]
    assert packed & 0x80, "the banner has a global colour table"
    tokens = _palette(build_site.STYLESHEET.read_text(encoding="utf-8"), dark=False)
    assert tokens["band"] == "#0d1117"
    table = gif[13 : 13 + 3 * (2 ** ((packed & 0x07) + 1))]
    colours = {"#" + table[i : i + 3].hex() for i in range(0, len(table), 3)}
    assert tokens["band"] in colours
