# p4p-camera-sdk

Reusable P4P relay/KCP and Ucon SD-card protocol primitives extracted from
reverse-engineering a cellular `B4HUNT` camera.

This is intentionally model- and firmware-specific. It provides protocol
building blocks and a relay session; it is not a universal camera driver.
Applications should depend on its small adapter-facing API rather than its
wire-format internals.

## Install

Install a pinned release in production:

```sh
pip install p4p-camera-sdk==0.1.12
```

Use the Git repository or an editable install only for SDK development. Tag
pushes matching `v*` build and publish the wheel through the release workflow;
configure PyPI Trusted Publishing for the `release` environment first.

The implementation was validated against real Ucon traffic: relay discovery,
KCP reassembly, SD event metadata, JPEG thumbnails, and MP4 file-data block
reassembly. Live integration tests require a real camera and credentials and
must never run in CI.
