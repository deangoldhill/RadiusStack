# Bundled MAC manufacturer registry

`manuf.gz` was retrieved on 2026-11-12 from Wireshark's canonical weekly registry:
https://www.wireshark.org/download/automated/data/manuf.gz

The registry header credits `tshark -G manuf` and says the underlying data is updated once a week. The API uses this bundled snapshot offline and attempts a bounded, in-memory refresh every seven days; device detail views never contact the registry.
