//! Who a container's connection comes from (plan §5.10): the runtime and container its process's cgroup names, with
//! the container's name, image, labels and Compose service from the runtime itself. Exact or nothing: a field that
//! can't be read stays empty, and rules on it don't match.
//!
//! - Docker: its API on `/run/docker.sock` (`GET /containers/<id>/json`).
//! - Podman: its own state, the SQLite database it keeps (rootful in `/var/lib/containers/storage`, rootless in the
//!   user's home), read-only: no socket needs to run.
//!
//! Looked up once per container (by cgroup id), on its first connection, and kept while it runs.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use snitchhiker_core::context::Container;
use tracing::debug;

const DOCKER_SOCKET: &str = "/run/docker.sock";
/// A lookup holds the first packet of a container's first connection: it must be quick, or give up.
const TIMEOUT: Duration = Duration::from_millis(500);
/// Containers remembered; past this many, the cache starts again (containers come and go).
const CAPACITY: usize = 4096;

/// What a cgroup path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub runtime: &'static str,
    /// The container's id (Docker, Podman, containerd, CRI-O), or its name (nspawn, LXC).
    pub id: String,
    /// The user a rootless container runs as.
    pub owner: Option<u32>,
}

/// The container a cgroup path (as `/proc/<pid>/cgroup` has it) belongs to, if it is one.
#[must_use]
pub fn named(path: &str) -> Option<Named> {
    let owner = path.split('/').find_map(|part| {
        part.strip_prefix("user@")?
            .strip_suffix(".service")?
            .parse::<u32>()
            .ok()
    });
    for part in path.split('/').rev() {
        let scoped = |prefix: &str| {
            part.strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(".scope"))
                .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(str::to_owned)
        };
        if let Some(id) = scoped("docker-") {
            return Some(Named {
                runtime: "docker",
                id,
                owner: None,
            });
        }
        if let Some(id) = scoped("libpod-") {
            return Some(Named {
                runtime: "podman",
                id,
                owner,
            });
        }
        if let Some(id) = scoped("cri-containerd-") {
            return Some(Named {
                runtime: "containerd",
                id,
                owner: None,
            });
        }
        if let Some(id) = scoped("crio-") {
            return Some(Named {
                runtime: "cri-o",
                id,
                owner: None,
            });
        }
        if let Some(name) = part
            .strip_prefix("systemd-nspawn@")
            .and_then(|rest| rest.strip_suffix(".service"))
        {
            return Some(Named {
                runtime: "nspawn",
                id: name.to_owned(),
                owner: None,
            });
        }
        if let Some(name) = part.strip_prefix("lxc.payload.") {
            return Some(Named {
                runtime: "lxc",
                id: name.to_owned(),
                owner: None,
            });
        }
    }
    None
}

/// A container looked up, with its identity's key (as the history keeps it), made once.
#[derive(Debug)]
pub struct Identified {
    pub container: Container,
    pub key: Arc<str>,
}

/// What was found for a key: a container, or that there is none.
type Found<K> = Mutex<HashMap<K, Option<Arc<Identified>>>>;

/// The containers looked up, by cgroup id; and the containers user-mode network helpers serve, by helper process
/// (pid and start time).
#[derive(Default)]
pub struct Contexts {
    containers: Found<u64>,
    helpers: Found<(u32, u64)>,
}

impl Contexts {
    /// The container process `pid` (in cgroup `cgroup`) runs in, if it runs in one that can be named.
    pub fn container(&self, pid: u32, cgroup: u64) -> Option<Arc<Identified>> {
        if let Some(known) = self
            .containers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&cgroup)
        {
            return known.clone();
        }
        let found = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|text| {
                // cgroup v2: one line, `0::<path>`.
                text.lines()
                    .find_map(|line| line.strip_prefix("0::").and_then(named))
            })
            .map(|named| {
                let container = describe(named);
                Arc::new(Identified {
                    key: Arc::from(container.key()),
                    container,
                })
            });
        let mut containers = self
            .containers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if containers.len() >= CAPACITY {
            containers.clear();
        }
        containers.insert(cgroup, found.clone());
        found
    }
}

impl Contexts {
    /// For a rootless container's user-mode network helper (pasta, slirp4netns): the container it connects for. The
    /// helper runs in the host's namespace and makes the container's connections itself; it serves exactly one
    /// namespace, named on its command line, and the container is the one whose processes are in it. `start`
    /// tells this helper from a later process with its pid.
    pub fn served_by(&self, helper: u32, start: u64, exe: &str) -> Option<Arc<Identified>> {
        if !is_network_helper(exe) {
            return None;
        }
        let mut helpers = self.helpers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(known) = helpers.get(&(helper, start)) {
            return known.clone();
        }
        let found = served_namespace(helper)
            .and_then(container_in_namespace)
            .map(|(pid, named)| {
                let container = describe(named);
                debug!(helper, pid, name = %container.name, "a network helper's container");
                Arc::new(Identified {
                    key: Arc::from(container.key()),
                    container,
                })
            });
        if helpers.len() >= CAPACITY {
            helpers.clear();
        }
        helpers.insert((helper, start), found.clone());
        found
    }
}

/// Whether `exe` is a user-mode network helper of rootless containers.
#[must_use]
pub fn is_network_helper(exe: &str) -> bool {
    let name = exe.rsplit('/').next().unwrap_or(exe);
    name == "pasta"
        || name == "slirp4netns"
        || name == "passt"
        || name.starts_with("passt.")
        || name.starts_with("pasta.")
}

/// The network namespace (its inode) a helper serves, from its command line: pasta's `--netns <path>` (or a pid as
/// its last argument), slirp4netns's target pid (or `--netns-type=path` and a path).
fn served_namespace(helper: u32) -> Option<u64> {
    let cmdline = std::fs::read(format!("/proc/{helper}/cmdline")).ok()?;
    let args: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    namespace_argument(&args).and_then(|target| match target {
        Target::Path(path) => namespace_at(helper, &path),
        Target::Pid(pid) => std::fs::metadata(format!("/proc/{pid}/ns/net"))
            .ok()
            .map(|m| std::os::unix::fs::MetadataExt::ino(&m)),
    })
}

/// The namespace mounted at `path` as the helper's runtime sees it. Rootless, the runtime mounts it in a mount
/// namespace of its own (from the host's, the path is an empty file), and the helper has since sandboxed itself into
/// an empty root: the path is resolved through the runtime's other processes, those in the helper's user namespace.
fn namespace_at(helper: u32, path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let user = std::fs::metadata(format!("/proc/{helper}/ns/user"))
        .ok()?
        .ino();
    // Namespace files are on nsfs, whose inodes are the namespaces'.
    let nsfs = std::fs::metadata("/proc/self/ns/net").ok()?.dev();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == helper
            || std::fs::metadata(format!("/proc/{pid}/ns/user"))
                .map(|m| m.ino())
                .ok()
                != Some(user)
        {
            continue;
        }
        if let Ok(found) = std::fs::metadata(format!("/proc/{pid}/root{path}"))
            && found.dev() == nsfs
        {
            return Some(found.ino());
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
enum Target {
    Path(String),
    Pid(u32),
}

/// Where a helper's arguments say its namespace is.
fn namespace_argument(args: &[String]) -> Option<Target> {
    let mut iter = args.iter().skip(1).peekable();
    let mut path_type = false;
    let mut last = None;
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--netns=") {
            return Some(Target::Path(value.to_owned()));
        }
        if arg == "--netns" {
            return iter.next().map(|path| Target::Path(path.clone()));
        }
        if arg == "--netns-type=path" {
            path_type = true;
        }
        if !arg.starts_with('-') {
            last = Some(arg.clone());
        }
    }
    // slirp4netns: `[options] <pid or path> <tap>`; the target is the argument before the tap's name.
    let positional: Vec<&String> = args
        .iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let target = if positional.len() >= 2 {
        positional.get(positional.len() - 2).map(|s| (*s).clone())
    } else {
        last
    }?;
    if path_type {
        Some(Target::Path(target))
    } else {
        target.parse().ok().map(Target::Pid)
    }
}

/// A container with a process in the network namespace `inode`, and that process.
fn container_in_namespace(inode: u64) -> Option<(u32, Named)> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(format!("/proc/{pid}/ns/net")) else {
            continue;
        };
        if std::os::unix::fs::MetadataExt::ino(&meta) != inode {
            continue;
        }
        let named = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("0::").and_then(named))
            });
        if let Some(named) = named {
            return Some((pid, named));
        }
    }
    None
}

/// A named container, with what its runtime says of it.
fn describe(named: Named) -> Container {
    let mut container = Container {
        runtime: named.runtime.to_owned(),
        owner: named.owner,
        ..Container::default()
    };
    let details = match named.runtime {
        "docker" => docker(&named.id),
        "podman" => podman(&named.id, named.owner),
        "nspawn" | "lxc" => {
            container.name.clone_from(&named.id);
            None
        }
        _ => None,
    };
    container.id = named.id;
    if let Some(details) = details {
        container.name = details.name;
        container.image = details.image;
        container.compose = compose(&details.labels);
        container.labels = details.labels;
    }
    container
}

/// What a runtime says of a container.
#[derive(Debug, Default, PartialEq, Eq)]
struct Details {
    name: String,
    image: String,
    labels: Vec<(String, String)>,
}

/// `project/service`, from the labels Compose (Docker's, or podman-compose) sets.
fn compose(labels: &[(String, String)]) -> Option<String> {
    let label = |key: &str| {
        labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let project = label("com.docker.compose.project")?;
    let service = label("com.docker.compose.service")?;
    Some(format!("{project}/{service}"))
}

/// The string at `pointer` in `json`, or nothing.
fn text(json: &serde_json::Value, pointer: &str) -> String {
    json.pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn labels_of(value: Option<&serde_json::Value>) -> Vec<(String, String)> {
    let mut labels: Vec<(String, String)> = value
        .and_then(serde_json::Value::as_object)
        .map_or_default(|map| {
            map.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect()
        });
    labels.sort();
    labels
}

/// Docker's API: `GET /containers/<id>/json`, over its socket.
fn docker(id: &str) -> Option<Details> {
    let answer = (|| -> std::io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(DOCKER_SOCKET)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        write!(
            stream,
            "GET /containers/{id}/json HTTP/1.0\r\nHost: docker\r\n\r\n"
        )?;
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer)?;
        Ok(answer)
    })()
    .inspect_err(|error| debug!(%error, "asking Docker about a container"))
    .ok()?;
    let split = answer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let (head, body) = answer.split_at(split + 4);
    if !head.starts_with(b"HTTP/1.0 200") && !head.starts_with(b"HTTP/1.1 200") {
        return None;
    }
    docker_details(body)
}

fn docker_details(body: &[u8]) -> Option<Details> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some(Details {
        name: text(&json, "/Name").trim_start_matches('/').to_owned(),
        image: text(&json, "/Config/Image"),
        labels: labels_of(json.get("Config").and_then(|c| c.get("Labels"))),
    })
}

/// Podman's state: the container's configuration in its database, rootful or in the owner's home.
fn podman(id: &str, owner: Option<u32>) -> Option<Details> {
    let storage = match owner {
        None => PathBuf::from("/var/lib/containers/storage"),
        Some(uid) => crate::process::home_of(uid)
            .map(|home| Path::new(&home).join(".local/share/containers/storage"))?,
    };
    let database = storage.join("db.sql");
    let connection = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .inspect_err(|error| debug!(%error, path = %database.display(), "opening Podman's database"))
    .ok()?;
    connection.busy_timeout(TIMEOUT).ok()?;
    // The JSON is kept as a BLOB.
    let config: Vec<u8> = connection
        .query_row(
            "SELECT JSON FROM ContainerConfig WHERE ID = ?1",
            [id],
            |row| row.get(0),
        )
        .inspect_err(|error| debug!(%error, "reading a container from Podman's database"))
        .ok()?;
    podman_details(std::str::from_utf8(&config).ok()?)
}

fn podman_details(config: &str) -> Option<Details> {
    let json: serde_json::Value = serde_json::from_str(config).ok()?;
    Some(Details {
        name: text(&json, "/name"),
        image: text(&json, "/rootfsImageName"),
        labels: labels_of(json.get("labels")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0133794d05ab40d47d94868c4fb19a4d610f6c97e3ee0c5ee5fcf8aa21c03ea9";

    #[test]
    fn cgroups_name_their_containers() {
        assert_eq!(
            named(&format!("/system.slice/docker-{ID}.scope")),
            Some(Named {
                runtime: "docker",
                id: ID.to_owned(),
                owner: None
            })
        );
        assert_eq!(
            named(&format!(
                "/user.slice/user-1001.slice/user@1001.service/user.slice/libpod-{ID}.scope/container"
            )),
            Some(Named {
                runtime: "podman",
                id: ID.to_owned(),
                owner: Some(1001)
            })
        );
        assert_eq!(
            named("/machine.slice/systemd-nspawn@build.service/payload").map(|n| n.id),
            Some("build".to_owned())
        );
        assert_eq!(named("/user.slice/user-1000.slice/session-2.scope"), None);
        assert_eq!(named("/system.slice/docker-notanid.scope"), None);
    }

    #[test]
    fn helpers_name_the_namespace_they_serve() {
        let args = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            namespace_argument(&args(
                "/usr/bin/pasta --config-net --dns-forward 169.254.1.1 -t none --quiet --netns /run/user/1001/netns/netns-6770"
            )),
            Some(Target::Path("/run/user/1001/netns/netns-6770".to_owned()))
        );
        assert_eq!(
            namespace_argument(&args(
                "/usr/bin/slirp4netns --disable-host-loopback --mtu=65520 -c -e 3 -r 4 4242 tap0"
            )),
            Some(Target::Pid(4242))
        );
        assert_eq!(
            namespace_argument(&args(
                "/usr/bin/slirp4netns --netns-type=path /run/user/1001/netns/n tap0"
            )),
            Some(Target::Path("/run/user/1001/netns/n".to_owned()))
        );
        assert!(is_network_helper("/usr/bin/passt.avx2"));
        assert!(is_network_helper("/usr/bin/slirp4netns"));
        assert!(!is_network_helper("/usr/bin/curl"));
    }

    #[test]
    fn docker_says_the_name_image_and_compose_service() {
        let body = br#"{"Name":"/shop-web-1","Config":{"Image":"node:22","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web","tier":"front"}}}"#;
        let details = docker_details(body).unwrap();
        assert_eq!(details.name, "shop-web-1");
        assert_eq!(details.image, "node:22");
        assert_eq!(compose(&details.labels).as_deref(), Some("shop/web"));
        assert!(
            details
                .labels
                .contains(&("tier".to_owned(), "front".to_owned()))
        );
    }

    #[test]
    fn podman_says_the_name_and_image() {
        let details = podman_details(
            r#"{"name":"db","rootfsImageName":"docker.io/library/postgres:17","labels":{"a":"b"}}"#,
        )
        .unwrap();
        assert_eq!(details.name, "db");
        assert_eq!(details.image, "docker.io/library/postgres:17");
        assert_eq!(details.labels, vec![("a".to_owned(), "b".to_owned())]);
    }
}
