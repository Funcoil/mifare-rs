Pure Rust implementation of Mifare protocol
===========================================

Warning
-------

This crate is work in progress and may permanently damage your tag. Also, the interface WILL change. Use with care (especially write methods), at your own risk!

About
-----

This crate implements basic Mifare operations - Authentication and Reading. It's designed to be reader-agnostic so in order to use it, you just need to `impl NFCTag for YourType`. However, it already has impl for PN532 reader (enabled via feature `with_pn532`).
