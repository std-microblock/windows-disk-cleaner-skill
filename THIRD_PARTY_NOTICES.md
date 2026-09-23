# Third-party notices

## MFTool

NTFS parsing approach reviewed against Kudaes/MFTool, commit
4441426e8c91a7acfe517ee42eb8130ad4a80cfc (Apache-2.0).
This project uses an independently rewritten bounds-checked streaming parser,
not MFTool's encrypted in-memory cache or file-content extraction functionality.
The license is included in licenses/MFTool-Apache-2.0.txt.
Source: https://github.com/Kudaes/MFTool

## librefs 0.1.0

MIT, copyright eWloYW8 / librefs contributors. License included in
licenses/librefs-MIT.txt. Used for boot-sector validation, standard information,
CRC32C and the read-only storage interface.
Source/API: https://docs.rs/librefs/0.1.0/librefs/

The crate's simplified B+tree row layout and CRC64 routine do not match the
ReFS 3.14 test volume. The application contains its own bounded raw B+tree
traversal and CRC-64/NVME implementation; it does not label the failed USN
enumeration path as a working fast backend.

ReFS research references (no unlicensed source code copied):

- libyal/libfsrefs structure specification: https://github.com/libyal/libfsrefs
- ReFS Forensics Reference: https://xbpt.gitlab.io/forefst/concepts/checksum_architecture/

## Slint 1.18.1

Copyright SixtyFPS GmbH and contributors. Desktop use is under Slint Royalty-free
Desktop, Mobile, and Web Applications License 2.0, included in
licenses/Slint-Royalty-free-2.0.md. The GUI exposes AboutSlint via its top-level
About button. Slint files are not relicensed by this project's Apache-2.0 license.
Source: https://github.com/slint-ui/slint

## Fluent System Icons

Selected unmodified 20px regular SVGs from Microsoft Fluent System Icons,
revision 8512d0121f6abd6c8c40f0bc4eb502ccd66ce6e7.
Copyright Microsoft Corporation, MIT. License included in
licenses/Fluent-System-Icons-MIT.txt and beside the SVG sources.
Source: https://github.com/microsoft/fluentui-system-icons

## Other Rust dependencies

Cargo.lock pins all transitive dependencies. Their upstream licenses and notices
remain applicable. This project does not redistribute dependency source code
under its own license.
