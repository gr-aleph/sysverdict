"""Checks for ATT&CK Collection, Exfiltration and Impact: packing files, copying them to
another drive or a transfer site, and ransom notes."""

import re

from triage.checks_common import FILE_IN_TEXT, add_finding, events_of, file_name
from triage.parse import to_datetime


# File endings a ransom note uses (a text or web page the victim is meant to open).
NOTE_ENDINGS = (".txt", ".html", ".htm", ".hta", ".url", ".rtf")


# Words typical of ransom-note file names, e.g. "RANSOM.txt", "how_to_recover.html",
# "restore-files.txt", "RESTORE_MY_FILES.txt". [_ -]? allows an optional underscore, space or
# dash between words. ("readme" is not on the list: every installer writes a readme.txt.)
RANSOM_NOTE = re.compile(r"ransom|decrypt|how[_ -]?to[_ -]?(recover|restore)|restore[_ -]?(my[_ -]?)?files")


def check_ransom_note(events, context):
    """Strong: a text or web file whose name looks like a ransom note, created (Event 11) or
    opened from a command line (Event 1). Other files, such as decrypt_test.py, are ignored."""
    found = {}
    for e in events_of(events, 11) + events_of(events, 1):
        text = e.get("TargetFilename", "") if e["event_id"] == 11 else e.get("CommandLine", "")
        if e["event_id"] == 11:
            names = [file_name(text)]
        else:
            # Words of the command line ("notepad RANSOM.txt") and full paths, which may contain
            # spaces ("C:\Users\a\Desktop\HOW TO RECOVER.txt").
            names = [file_name(part.strip('"')) for part in text.split()]
            names += [file_name(path) for path in FILE_IN_TEXT.findall(text)]
        is_note = False
        for name in names:
            if name.endswith(NOTE_ENDINGS) and RANSOM_NOTE.search(name):
                is_note = True
        if is_note:
            if e["event_id"] == 11:   # the program that wrote the note
                actor, guid = e.get("Image", ""), e.get("ProcessGuid", "")
            else:                     # the program that opened the note (e.g. in Notepad)
                actor, guid = e.get("ParentImage", ""), e.get("ParentProcessGuid", "")
            add_finding(found, "ransom", e, "ransom_note", "Possible ransom note", "Strong",
                        actor, f"{file_name(actor)}: {text[:200]}", guid)
    return list(found.values())


# Packing files into an archive (ATT&CK T1560.001 Archive via Utility; collecting files in one
# place is also T1074.001 Local Data Staging). Dual-use: people zip files every day, so Low.
#   7z/7za/7zr/7zg/rar/winrar with the "a" (add) command: "7z a out.7z C:\docs"
#   tar with a "c" (create) option: "tar -czf out.tgz docs"; Compress-Archive; makecab
#   (?<![\w.])tar = "tar" as a program, not the end of "a.tar"; (?-i:...) = this part is
#   case-sensitive, because tar's -C (capital) means "change folder", not "create".
ARCHIVE_COMMAND = re.compile(r"\b(7z[arg]?|rar|winrar)(\.exe)?\"?\s+a\s|"
                             r"(?<![\w.])tar(\.exe)?\"?\s+-?(?-i:[a-z]*c[a-z]*)\s|"
                             r"compress-archive\b|\bmakecab(\.exe)?\b", re.IGNORECASE)


# The archive file named after "7z a" / "rar a" (options such as -p or -tzip may come first).
ARCHIVE_NAME = re.compile(r"\b(?:7z[arg]?|rar|winrar)(?:\.exe)?\"?\s+a\s+(?:-\S+\s+)*\"?([^\"\s]+)",
                          re.IGNORECASE)


# Endings an archive file really has (.001 = the first part of a split archive).
ARCHIVE_ENDINGS = (".7z", ".zip", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".001")


def check_archive(events, context):
    """Weak: files were packed into an archive (dual-use).
    Strong: the archive got a non-archive ending ("7z a holiday.jpg docs\\"), which disguises it as
    another file type (T1036.008 Masquerade File Type): no common legitimate use."""
    found = {}
    for e in events_of(events, 1):
        command = e.get("CommandLine", "")
        if not ARCHIVE_COMMAND.search(command):
            continue
        name_match = ARCHIVE_NAME.search(command)
        archive = file_name(name_match.group(1)) if name_match else ""
        # 7-Zip and RAR add their own ending to a name without one, so only a different ending counts.
        disguised = "." in archive and not archive.endswith(ARCHIVE_ENDINGS)
        if disguised:
            title, strength = "Archive disguised as another file type", "Strong"
        else:
            title, strength = "Files packed into an archive", "Weak"
        add_finding(found, (file_name(e.get("Image")), title), e, "archive", title, strength,
                    e.get("Image", ""), f"{file_name(e.get('Image'))}: {command[:180]}", e.get("ProcessGuid", ""))
        if disguised:
            found[(file_name(e.get("Image")), title)].update(
                {"tactic": "Defense Evasion", "technique": "T1036.008 Masquerade File Type"})
    return list(found.values())


# A "bulk copy": a person saves a few files to a USB stick; copying a folder writes dozens within
# minutes. 20 files in 10 minutes separates the two (a judgement from how people work, not from
# any log). Exfiltration over USB is ATT&CK T1052.001. Sysmon cannot tell a USB stick from another
# drive, so every drive except C: counts (a network drive is a copy-out too). Dual-use: Low.
BULK_FILES, BULK_SECONDS = 20, 600


OTHER_DRIVE = re.compile(r"^[a-bd-z]:\\", re.IGNORECASE)


def check_copy_to_other_drive(events, context):
    """Weak: 20+ files, or any archive, written to a drive other than C: within 10 minutes."""
    by_drive = {}
    for e in events_of(events, 11):
        path = e.get("TargetFilename", "")
        if OTHER_DRIVE.match(path) and ":zone.identifier" not in path.lower():
            by_drive.setdefault(path[0].upper(), []).append(e)

    found = {}
    for drive, files in by_drive.items():
        files.sort(key=lambda e: e["time"])
        for first in files:
            start = to_datetime(first["time"])
            window = [f for f in files if 0 <= (to_datetime(f["time"]) - start).total_seconds() <= BULK_SECONDS]
            archives = [f for f in window if f.get("TargetFilename", "").lower().endswith(ARCHIVE_ENDINGS)]
            if len(window) >= BULK_FILES or archives:
                proof = window if len(window) >= BULK_FILES else archives
                for f in proof:
                    add_finding(found, drive, f, "copy_to_other_drive", "Files copied to another drive (USB?)",
                                "Weak", f.get("Image", ""), f"{len(window)} file(s) written to drive {drive}: "
                                f"within 10 minutes (archives: {len(archives)})", f.get("ProcessGuid", ""))
                break  # one finding per drive is enough
    return list(found.values())


# File-transfer services and tools that attackers use to upload stolen data (ATT&CK T1567.002
# Exfiltration to Cloud Storage; incident reports most often name MEGA with rclone or MEGAsync,
# and one-off transfer sites). Mainstream storage (Dropbox, Google Drive, OneDrive) is left out:
# nearly every normal computer uses one. Dual-use: Low.
TRANSFER_SITES = ("mega.nz", "mega.co.nz", "mega.io", "wetransfer.com", "we.tl", "file.io", "gofile.io",
                  "transfer.sh", "sendspace.com", "pixeldrain.com", "catbox.moe", "anonfiles.com",
                  "bashupload.com", "temp.sh", "filebin.net", "ufile.io")


TRANSFER_TOOLS = ("rclone", "megasync", "megacmd", "megatools")


def check_cloud_upload(events, context):
    """Weak: a file-transfer site was looked up, or an upload tool such as rclone ran."""
    found = {}
    for e in events_of(events, 22):
        domain = e.get("QueryName", "").lower().rstrip(".")
        site = next((s for s in TRANSFER_SITES if domain == s or domain.endswith("." + s)), None)
        if site:
            add_finding(found, site, e, "cloud_upload", "File-transfer site used", "Weak", e.get("Image", ""),
                        f"{file_name(e.get('Image'))} looked up {domain}", e.get("ProcessGuid", ""))
    for e in events_of(events, 1):
        name = file_name(e.get("Image"))
        if name.startswith(TRANSFER_TOOLS):
            add_finding(found, name, e, "cloud_upload", "Upload tool ran", "Weak", e.get("Image", ""),
                        f"{name}: {e.get('CommandLine', '')[:180]}", e.get("ProcessGuid", ""))
    return list(found.values())
