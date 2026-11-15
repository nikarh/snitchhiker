# The app is setgid to the client group (made by the snitchhiker package), and registered as a trusted client of the
# daemon, pinned to this version's digest (docs/decisions/0006-client-trust.md).
chgrp snitchhiker-ui /usr/bin/snitchhiker-ui
chmod 2755 /usr/bin/snitchhiker-ui
snitchhikerd trust-client /usr/bin/snitchhiker-ui >/dev/null
