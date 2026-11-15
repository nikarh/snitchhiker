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
    /// The identity as one line, as the history keeps it: runtime, id, name, image, Compose service and owner,
    /// tab-separated (none of them holds a tab). Labels are for rules only and aren't kept.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.runtime,
            self.id,
            self.name,
            self.image,
            self.compose.as_deref().unwrap_or_default(),
            self.owner.map_or_else(String::new, |uid| uid.to_string())
        )
    }

    /// The identity a [`Container::key`] wrote.
    #[must_use]
    pub fn from_key(key: &str) -> Self {
        let mut parts = key.split('\t');
        let mut next = || parts.next().unwrap_or_default().to_owned();
        let (runtime, id, name, image, compose, owner) =
            (next(), next(), next(), next(), next(), next());
        Self {
            runtime,
            id,
            name,
            image,
            compose: (!compose.is_empty()).then_some(compose),
            labels: Vec::new(),
            owner: owner.parse().ok(),
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_without_labels() {
        let container = Container {
            runtime: "podman".to_owned(),
            id: "abc".to_owned(),
            name: "db".to_owned(),
            image: "docker.io/library/postgres:17".to_owned(),
            compose: Some("shop/db".to_owned()),
            labels: vec![("a".to_owned(), "b".to_owned())],
            owner: Some(1001),
        };
        assert_eq!(
            Container::from_key(&container.key()),
            Container {
                labels: Vec::new(),
                ..container
            }
        );
        assert_eq!(Container::from_key("docker\tid\tname\t\t\t").compose, None);
    }
}
