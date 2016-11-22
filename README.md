Pure Rust implementation of Mifare protocol
===========================================

This crate implements basic Mifare operations - Authentication and Reading. It's designed to be reader-agnostic so in order to use it, you just need to `impl NFCTag for YourType`. However, it already has impl for PN532 reader (enabled via feature `with_pn532`).

It's still WIP. Use at your own risk!
