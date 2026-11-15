# The app is setgid to the client group (made by the snitchhiker package), and registered as a trusted client of the
# daemon, pinned to this version's digest (docs/decisions/0006-client-trust.md).
chgrp snitchhiker-ui /usr/bin/snitchhiker-ui
chmod 2755 /usr/bin/snitchhiker-ui
snitchhikerd trust-client /usr/bin/snitchhiker-ui >/dev/null
# The app's caches of history: only the app (setgid to the group) can enter this directory.
install -d -o root -g snitchhiker-ui -m 0770 /var/cache/snitchhiker-ui
# The remote nodes it knows and this device's key: the user's other processes mustn't read the key.
install -d -o root -g snitchhiker-ui -m 0770 /var/lib/snitchhiker-ui
