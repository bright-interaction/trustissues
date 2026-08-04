# Planted egress bypasses that must not compile

Each directory here is a write path somebody could plausibly write, aimed at one
of the four vault_entries columns that decide where a decrypted secret is sent.
None of them may build.

`testdata` is invisible to `go build ./...` and `go test ./...`, so these do not
break the tree. `TestPlantedEgressBypassesDoNotCompile` names each package
explicitly, runs the real toolchain on it, and requires a refusal with the
expected diagnostic. If one of them ever builds, that test fails and prints the
bypass that succeeded.

This is the difference from round 5. That round proved the same property by
reading the source and matching regular expressions against it, and four planted
bypasses walked through the gaps in the patterns while building clean, vetting
clean and passing all four guards. A pattern can be spelled around; a symbol
that does not exist cannot be called.
