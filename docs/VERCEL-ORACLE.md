# Vercel frontend and Oracle backend

Status: deployment preparation only. No Oracle VM or Vercel deployment has been created. OAuth and ARM compatibility still need live verification. Hosting does not finish the enterprise features listed in STATUS.md.

## Account setup

The account owner must register at https://signup.cloud.oracle.com/ and complete identity/card verification. Select only resources marked Always Free eligible and confirm the account's actual allowance. Capacity is not guaranteed; idle instances can be reclaimed. Do not upgrade to paid resources just to bypass a capacity error without reviewing cost.

Connect the Vercel integration in ChatGPT, or import Yemireddy-Pragnavi/app_doc in the Vercel dashboard. The repository's vercel.json selects Next.js explicitly; its default npm build is for the existing Sites preview and must not be used for Vercel.

## Backend compatibility gate

Oracle Ampere A1 is ARM64. Before deploying user data, build both backend and browser images natively on ARM64 and run the container integration smoke test from backend/tests/stack_smoke.py. Verify the pinned Gitleaks image, Semgrep installation and sandboxed Chromium on that host. The previous successful GitHub container check is not proof of ARM compatibility.

Preserve browser network_mode:none, its shared Unix socket, dropped capabilities and seccomp profile. Do not disable Chromium sandboxing to make a deployment pass. Run scans serially initially. Keep the database and Redis off the public internet and back up persistent database volumes.

The existing compose.yaml provides the backend services. Once Docker and a private .env are configured, start db redis api worker browser scheduler. The production override also deploys the frontend and assumes a custom hostname; it is not an Oracle/Vercel deployment script.

Expose only the API through a properly configured HTTPS reverse proxy. A backend HTTPS hostname/certificate or another verified secure origin must be arranged before configuring the Vercel rewrite. A purchased domain is not required for the Vercel frontend, but Vercel's hostname does not automatically provide HTTPS to an arbitrary VM IP.

## Vercel environment

Use the stable production URL, not a changing preview URL. Configure:

- BACKEND_ORIGIN=https://YOUR_VERIFIED_BACKEND_HOST (server-side configuration, no trailing path)
- NEXT_PUBLIC_API_URL=/backend

Then redeploy. The /backend prefix is removed before forwarding to the backend. If the backend is not ready, leave these variables unset and retain the labeled sample preview. No credentials belong in NEXT_PUBLIC variables.

## Backend environment and OAuth

Set privately on the backend:

- FRONTEND_URL=https://YOUR_PROJECT.vercel.app
- GITHUB_CALLBACK_URL=https://YOUR_PROJECT.vercel.app/backend/api/auth/callback
- COOKIE_SECURE=true
- GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET from the owner's GitHub OAuth app
- SESSION_SECRET, TOKEN_ENCRYPTION_KEY, POSTGRES_PASSWORD (strong separately generated secrets)

Register the identical callback in GitHub. Preserve SameSite=Lax, HttpOnly cookies and CSRF origin checks. Do not loosen them to compensate for an incorrectly configured proxy.

## Acceptance before calling it live

Test HTTPS, /backend/health, sign-in and sign-out, browser cookie persistence, a real authorized repository scan, persisted scan history after restart, a runtime scan of an authorized staging URL, and failed/missing-engine decisions. Check responses containing user data are not cached by Vercel. Test an unauthorized account cannot read another account's repositories. Verify webhook signatures and an exact-commit CI gate with configured test repositories. Keep live credentials and private repository contents out of logs.
