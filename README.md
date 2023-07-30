# Cloud Core Utils
This package is for giving utils to other Rust servers such as:

- JWT
- Config
- error handling for server endpoints
- runtime state

These will help the developer use these tools outside of the box to have uniform runtime states, config handles, and error handling for
api endpoints. This will enable developers to fuse servers together to call endpoints via memory. 

## Installing
To install you merely need the following in your `Cargo.toml`:

```toml
cloud_core_utils = { git = "https://github.com/yellow-bird-consult/cloud-core-utils.git", branch = "main" }
```

Your build might not automatically work and this is because you have not setup your git credentials for `cargo`. To setup the credentials
we need to open the `~/.cargo/config` file and add the following:
```
[net]
git-fetch-with-cli = true
```

This will enable your `cargo` toolchain to use git to extract cargo packages.
