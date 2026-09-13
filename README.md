# searchbarthatknowseverythingaboutyou

A local and GitHub Pages search bar that looks up public information and answers with OpenRouter.

## Local

1. Copy `.env.example` to `.env` and add your keys
2. Double-click `start.bat` or run `npm start`
3. Open `http://localhost:8080`

Python is not used.

## GitHub Pages

The site deploys from `main` with GitHub Actions. Set these repository secrets:

- `OPENROUTER_API_KEY` (required for chat on the live site)
- `OPENROUTER_MODEL` (optional, defaults to `openai/gpt-4o-mini`)

Do not commit `.env`. The GitHub token stays on your machine / in GitHub secrets for deploy only. It is never written into the published site.

The published `config.js` includes the OpenRouter key so the static site can chat. Anyone who opens the live page can read that key. Use a limited OpenRouter key.

## Optional keys in `.env`

- `OPENROUTER_API_KEY` — chat and summaries
- `GITHUB_TOKEN` — higher GitHub lookup limits on the local server
- `GROQ_API_KEY` — local fallback if OpenRouter fails
- `HIBP_API_KEY` — email breach checks on the local server
- `VIRUSTOTAL_API_KEY` — IP reputation on the local server
- `IPINFO_TOKEN` — more detailed IP lookups on the local server
- `HUNTER_API_KEY` / `ABSTRACT_API_KEY` — reserved for later email/phone lookups

The live site also uses public lookups that need no key: ipwho.is, Google DNS, and the public GitHub user API.
