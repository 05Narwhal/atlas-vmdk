# atlas-vmdk

Opens VMware virtual disks as a `BlockSource`: monolithic sparse and stream-optimized (compressed) files, and descriptor files over flat and sparse extents.

- Descriptor files are size-limited and every extent is checked against its file. Images with a parent are reported as unsupported.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
