package config

// ChartArchiveLimit is the single accepted size boundary for every chart
// entering desired state, local publication, or the internal registry.
const ChartArchiveLimit int64 = 64 << 20

// SeedAssetLimit bounds bootstrap executables and installers retained in a
// minimal seed payload. Container layers use the streaming OCI path instead.
const SeedAssetLimit int64 = 16 << 20
