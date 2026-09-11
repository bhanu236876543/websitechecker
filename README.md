# WebsiteChecker

WebsiteChecker generates an easy-to-read, defensive security report from a public website URL and/or public GitHub repository URL.

## What it does

- Safely validates outbound URLs and blocks localhost, private IPs, cloud metadata, and non-HTTP(S) schemes.
- Checks HTTPS, common browser security headers, cookie attributes, HTTP response status, and public server disclosure.
- Inspects public GitHub metadata and filenames without reading or displaying repository secrets.
- Applies a deterministic 100-point score based only on scanner findings.
- Includes a labeled demo mode for reliable hackathon demonstrations.

## Stack

Next.js 15, React 19, TypeScript, and plain CSS.

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000` and use Demo Mode or enter public URLs.

## Deploy

The quickest production deployment is Vercel:

1. Push this folder to a new GitHub repository.
2. Import the repository in [Vercel](https://vercel.com/new).
3. Keep the detected Next.js settings and deploy.
4. After deployment, test Demo Mode and one public website URL from the deployed address.

No environment variables are required for the MVP. GitHub repository inspection uses the public GitHub API, so its unauthenticated request limits apply.

## API

`POST /api/analyze`

```json
{ "websiteUrl": "https://example.com", "githubUrl": "https://github.com/vercel/next.js" }
```

The endpoint returns a complete analysis object. This MVP returns the report in the same response rather than persisting it.

## Security boundaries

This tool performs safe, non-destructive checks of public targets only. It does not exploit vulnerabilities, brute-force, authenticate, or expose discovered secret values. Automated reports are not a guarantee of complete security.

Private, local, cloud-metadata, and non-HTTP(S) destinations are rejected. Redirect destinations are validated before they are requested. The analysis endpoint has a lightweight in-memory request limit; a high-traffic deployment should replace it with a shared rate-limit service.

## Future improvements

Add database persistence and polling endpoints, certificate-expiry detail, GitHub code scanning via an authenticated opt-in integration, and optional AI-generated explanations that only consume structured scanner output.
