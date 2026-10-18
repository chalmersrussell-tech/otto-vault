"""XML import/export (interchange only; the live vault stays encrypted).
Throwaway vaults in temp dirs only."""
import os
import sys
import time
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vault as V  # noqa: E402

PW = "test-master-pw-123"


@pytest.fixture
def v(tmp_path):
    return V.Vault.create(str(tmp_path / "v" / "vault.dat"), PW)


def write(tmp_path, text, name="f.xml", enc="utf-8"):
    p = tmp_path / name
    p.write_bytes(text.encode(enc) if isinstance(text, str) else text)
    return str(p)


# ------------------------------------------------------------- export
def test_export_schema_and_roundtrip(v, tmp_path):
    v.add_entry("Bank & <Co>", "bob \"b\"", "p&ss<w>rd'\"]]>", "https://x.example/?a=1&b=2",
                "line1\nline2\ttab")
    v.add_entry("Second", "", "  spaced  ")
    out = str(tmp_path / "out.xml")
    assert v.export_xml(out) == (2, 0)
    raw = open(out, "rb").read()
    assert raw.startswith(b'<?xml version="1.0" encoding="UTF-8"?>\n<ottovault version="1">')
    assert b"UNENCRYPTED" in raw
    root = ET.parse(out).getroot()
    assert root.tag == "ottovault" and root.get("version") == "1"
    ents = root.findall("entry")
    assert [[c.tag for c in e] for e in ents] == [["title", "username", "password", "url", "notes"]] * 2
    # round trip into a fresh vault
    w = V.Vault.create(str(tmp_path / "w" / "vault.dat"), PW)
    assert w.import_xml(out) == (2, 0)
    a = {e["title"]: e for e in w.list_entries()}
    b = a["Bank & <Co>"]
    assert (b["username"], b["password"], b["url"], b["notes"]) == (
        "bob \"b\"", "p&ss<w>rd'\"]]>", "https://x.example/?a=1&b=2", "line1\nline2\ttab")
    assert a["Second"]["password"] == "  spaced  "           # whitespace preserved


def test_export_marks_ai_access_informationally_and_import_ignores_it(v, tmp_path):
    v.add_entry("A", "u", "p", otto_approved=True)
    v.add_entry("B", "u", "p")
    out = str(tmp_path / "o.xml")
    v.export_xml(out)
    ents = {e.findtext("title"): e for e in ET.parse(out).getroot().findall("entry")}
    assert ents["A"].get("ai_access") == "true"
    assert ents["A"].get("ai_access_until") == time.strftime("%Y-%m-%d", time.localtime(
        v.list_entries()[0]["otto_expires"]))
    assert ents["B"].get("ai_access") is None
    out2 = str(tmp_path / "o2.xml")
    v.export_xml(out2, include_ai_info=False)
    assert b"ai_access" not in open(out2, "rb").read()
    w = V.Vault.create(str(tmp_path / "w" / "vault.dat"), PW)
    assert w.import_xml(out) == (2, 0)
    assert w.approved_count() == 0                         # NEVER auto-approved
    assert all(e["otto_expires"] is None for e in w.list_entries())


def test_export_skips_entries_xml_cannot_carry_and_is_atomic(v, tmp_path):
    v.add_entry("Good", "u", "p")
    v.add_entry("Legacy", "u", "p")
    for e in v._data["entries"]:                           # an entry from before the input rules
        if e["title"] == "Legacy":
            e["notes"] = "bad\x00char"
    out = str(tmp_path / "o.xml")
    assert v.export_xml(out) == (1, 1)
    ET.parse(out)                                          # still well-formed
    assert [f for f in os.listdir(tmp_path) if f.endswith(".tmp")] == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_export_file_is_owner_only(v, tmp_path):
    out = str(tmp_path / "o.xml")
    v.export_xml(out)
    assert os.stat(out).st_mode & 0o077 == 0


def test_export_does_not_change_the_vault_file(v, tmp_path):
    v.add_entry("A", "u", "p")
    before = open(v.path, "rb").read()
    v.export_xml(str(tmp_path / "o.xml"))
    assert open(v.path, "rb").read() == before
    assert b"<ottovault" not in before                      # live vault is still encrypted JSON


def test_verify_master_password(v):
    assert v.verify_master_password(PW) is True
    assert v.verify_master_password(PW + "x") is False


# ------------------------------------------------------------- import
def test_import_ottovault_xml_validates_dedupes_and_never_approves(v, tmp_path):
    xml = '''<?xml version="1.0" encoding="UTF-8"?>
<ottovault version="1">
  <!-- comment -->
  <entry ai_access="true"><title> A   B </title><username>u</username><password>p1</password>
    <url>http://a</url><notes>n</notes></entry>
  <entry><title>A B</title><username>u</username><password>p1</password><url>http://a</url><notes>n</notes></entry>
  <entry><title>Too long</title><password>%s</password></entry>
  <entry><title>Bidi&#x202E;</title><password>x</password></entry>
  <entry><title></title><url>http://only.example</url><password>x</password></entry>
  <entry><title>Extra</title><password>x</password><bogus>1</bogus><notes><b>nested</b></notes></entry>
</ottovault>''' % ("p" * 2000)
    p = write(tmp_path, xml)
    assert v.import_xml(p) == (3, 3)
    r = v.last_xml_report
    assert r == {"format": "OttoVault XML", "added": 3, "duplicates": 1, "invalid": 2, "unsupported": 0}
    titles = sorted(e["title"] for e in v.list_entries())
    assert titles == ["A B", "Extra", "http://only.example"]
    assert v.approved_count() == 0
    assert v.import_xml(p) == (0, 6)                        # second time: all duplicates/invalid
    assert V.Vault.open(v.path, PW).list_entries()[0]["otto_approved"] is False


def test_import_unknown_version_and_root_rejected(v, tmp_path):
    with pytest.raises(V.VaultError, match="version"):
        v.import_xml(write(tmp_path, '<ottovault version="9"/>'))
    with pytest.raises(V.VaultError, match="Not an OttoVault or KeePass"):
        v.import_xml(write(tmp_path, "<html><body/></html>"))
    assert v.list_entries() == []


@pytest.mark.parametrize("content", [b"", b"not xml at all", b"<ottovault><entry></ottovault>",
                                     b"\x00\x01\x02binary", b"<a/><b/>",
                                     "<ottovault><entry><title>x&#0;</title></entry></ottovault>".encode()])
def test_malformed_files_give_clear_error_not_crash(v, tmp_path, content):
    with pytest.raises(V.VaultError):
        v.import_xml(write(tmp_path, content))
    assert v.list_entries() == []


def test_missing_file_and_bad_encoding(v, tmp_path):
    with pytest.raises(V.VaultError):
        v.import_xml(str(tmp_path / "nope.xml"))
    with pytest.raises(V.VaultError, match="UTF"):
        v.import_xml(write(tmp_path, b"<ottovault><entry><title>\xe9\xff</title></entry></ottovault>"))


def test_utf16_and_bom_utf8_accepted(v, tmp_path):
    xml = '<?xml version="1.0" encoding="UTF-16"?><ottovault><entry><title>Caf\u00e9</title><password>p</password></entry></ottovault>'
    assert v.import_xml(write(tmp_path, xml, "u16.xml", "utf-16")) == (1, 0)
    xml8 = '<?xml version="1.0" encoding="UTF-8"?><ottovault><entry><title>\u4e2d\u6587</title><password>p</password></entry></ottovault>'
    assert v.import_xml(write(tmp_path, b"\xef\xbb\xbf" + xml8.encode(), "bom.xml")) == (1, 0)
    assert sorted(e["title"] for e in v.list_entries()) == ["Caf\u00e9", "\u4e2d\u6587"]


# ------------------------------------------------------------- safety
def test_billion_laughs_refused_quickly(v, tmp_path):
    lol = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
           '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
           '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
           '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]>'
           '<ottovault><entry><title>&lol4;</title><password>p</password></entry></ottovault>')
    t0 = time.time()
    with pytest.raises(V.VaultError, match="DOCTYPE"):
        v.import_xml(write(tmp_path, lol))
    assert time.time() - t0 < 2 and v.list_entries() == []


def test_external_entity_xxe_refused_and_nothing_read(v, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-FILE-CONTENT")
    xxe = ('<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file://%s">]>'
           '<ottovault><entry><title>t</title><notes>&x;</notes><password>p</password></entry></ottovault>'
           % str(secret).replace("\\", "/"))
    with pytest.raises(V.VaultError):
        v.import_xml(write(tmp_path, xxe))
    assert v.list_entries() == []
    for t in ("<!DOCTYPE x>", "<!doctype x>", "<!ENTITY a 'b'>"):     # any spelling
        with pytest.raises(V.VaultError):
            v.import_xml(write(tmp_path, t + "<ottovault/>"))


def test_oversize_file_refused_without_reading_it_all(v, tmp_path):
    p = tmp_path / "big.xml"
    with open(p, "wb") as f:
        f.write(b"<ottovault>")
        f.write(b" " * (V.XML_MAX_BYTES + 10))
        f.write(b"</ottovault>")
    with pytest.raises(V.VaultError, match="too large"):
        v.import_xml(str(p))


def test_entry_count_cap(v, tmp_path, monkeypatch):
    monkeypatch.setattr(V, "XML_MAX_ENTRIES", 3)
    body = "".join("<entry><title>t%d</title><password>p</password></entry>" % i for i in range(4))
    with pytest.raises(V.VaultError, match="Too many"):
        v.import_xml(write(tmp_path, "<ottovault>%s</ottovault>" % body))
    assert v.list_entries() == []


# ------------------------------------------------------------- KeePass
KEEPASS = '''<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><Generator>KeePass</Generator></Meta>
  <Root>
    <Group><Name>Database</Name>
      <Entry>
        <String><Key>Notes</Key><Value>kp notes</Value></String>
        <String><Key>Password</Key><Value ProtectInMemory="True">kp-pass-1</Value></String>
        <String><Key>Title</Key><Value>KP Site</Value></String>
        <String><Key>URL</Key><Value>https://kp.example</Value></String>
        <String><Key>UserName</Key><Value>kpuser</Value></String>
        <String><Key>Custom</Key><Value>ignored</Value></String>
        <History><Entry>
          <String><Key>Title</Key><Value>OLD VERSION</Value></String>
          <String><Key>Password</Key><Value>old-pass</Value></String>
        </Entry></History>
      </Entry>
      <Group><Name>Sub</Name>
        <Entry>
          <String><Key>Title</Key><Value>Nested</Value></String>
          <String><Key>Password</Key><Value></Value></String>
        </Entry>
        <Entry>
          <String><Key>Title</Key><Value>Encrypted</Value></String>
          <String><Key>Password</Key><Value Protected="True">Y2lwaGVydGV4dA==</Value></String>
        </Entry>
      </Group>
      <Group><Name>Recycle Bin</Name>
        <Entry><String><Key>Title</Key><Value>Trashed</Value></String></Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>'''


def test_keepass_xml_subset(v, tmp_path):
    p = write(tmp_path, KEEPASS)
    assert v.import_xml(p) == (2, 1)
    assert v.last_xml_report == {"format": "KeePass 2.x XML", "added": 2, "duplicates": 0,
                                 "invalid": 0, "unsupported": 1}
    got = {e["title"]: e for e in v.list_entries()}
    assert sorted(got) == ["KP Site", "Nested"]               # history, recycle bin, encrypted skipped
    k = got["KP Site"]
    assert (k["username"], k["password"], k["url"], k["notes"]) == (
        "kpuser", "kp-pass-1", "https://kp.example", "kp notes")
    assert v.approved_count() == 0
    assert v.import_xml(p) == (0, 3)


def test_keepass_without_root_rejected(v, tmp_path):
    with pytest.raises(V.VaultError, match="Root"):
        v.import_xml(write(tmp_path, "<KeePassFile><Meta/></KeePassFile>"))


def test_imported_xml_never_logs_or_leaks_passwords(v, tmp_path, capsys):
    p = write(tmp_path, '<ottovault><entry><title>S</title><password>Zq-secret-xml-99</password></entry></ottovault>')
    v.import_xml(p)
    out = capsys.readouterr()
    assert "Zq-secret-xml-99" not in out.out + out.err
    assert b"Zq-secret-xml-99" not in open(v.path, "rb").read()      # vault stays encrypted
    assert "Zq-secret-xml-99" not in str(v.last_xml_report)
