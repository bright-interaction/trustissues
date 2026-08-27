package handlers

// MaxNativeVaultFileBytes is the native-v1 interchange file ceiling. Export
// and import must share this exact value: accepting an export that the native
// decoder cannot read back would turn a successful backup into false safety.
//
// The exported name lets the HTTP body-limit middleware reserve multipart
// overhead without restating the 10 MiB file limit in another package.
const MaxNativeVaultFileBytes = 10 << 20
