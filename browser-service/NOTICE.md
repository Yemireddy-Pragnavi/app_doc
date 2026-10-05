# Browser sandbox profile

`seccomp_profile.json` is copied unmodified from Microsoft Playwright's `utils/docker/seccomp_profile.json`, retrieved 4 October 2026. It extends Docker's default syscall allowlist for the Chromium user-namespace sandbox. Upstream: https://github.com/microsoft/playwright/blob/main/utils/docker/seccomp_profile.json

Apache License 2.0 is included in `LICENSE.playwright`. Keep Chromium sandboxing enabled. If the host blocks user namespaces, repair host configuration or keep browser coverage unavailable; do not silently launch without the sandbox.

Local modification: clone3 returns ENOSYS (38), preserving clone filtering and allowing libc fallback on modern distributions.
Local modification: permit the chroot syscall for Chromium namespace sandbox initialization. No container capability is granted; kernel namespace permissions still apply.
