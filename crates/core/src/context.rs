//! Who a connection's sender is beyond the host (plan §5.10): a container's identity, a VM's, a network namespace's
//! name. Known exactly or not at all: a field that couldn't be read is empty, and conditions on it don't match.

/// A container, as rules see it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Container {
    /// `docker`, `podman`, `containerd`, `cri-o`, `nspawn`, `lxc`.
    pub runtime: String,
    pub id: String,
    pub name: String,
    /// The image reference it was created from (`docker.io/library/node:22`).
    pub image: String,
    /// The Compose project and service: `project/service`.
    pub compose: Option<String>,
    pub labels: Vec<(String, String)>,
    /// For a rootless runtime: the user it runs as.
    pub owner: Option<u32>,
}

impl Container {
    /// How people know it: the Compose service, or the name, with the image.
    #[must_use]
    pub fn label(&self) -> String {
        let name = self.compose.as_deref().unwrap_or(&self.name);
        if self.image.is_empty() {
            name.to_owned()
        } else {
            format!("{name} ({})", self.image)
        }
    }
}

/// A virtual machine, as rules see it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Vm {
    /// `qemu`, `firecracker`, ...
    pub hypervisor: String,
    pub name: String,
    pub uuid: String,
}
