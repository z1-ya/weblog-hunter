# Repository Setup and Configuration Guide

This document provides instructions for repository maintainers on configuring the GitHub repository for weblog-hunter.

## Table of Contents

- [GitHub Repository Topics](#github-repository-topics)
- [Branch Protection Rules](#branch-protection-rules)
- [GitHub Actions Secrets](#github-actions-secrets)
- [GitHub Pages](#github-pages-optional)
- [Repository Settings](#repository-settings)
- [Third-Party Integrations](#third-party-integrations)

## GitHub Repository Topics

Topics help users discover your repository. Add the following topics through GitHub's repository settings:

### How to Add Topics

1. Go to https://github.com/shalbuzov/weblog-hunter
2. Click on the gear icon ⚙️ next to "About" (on the right side)
3. Add the following topics in the "Topics" field:

### Recommended Topics

```
security
log-analysis
threat-hunting
python
cybersecurity
apache-logs
nginx-logs
web-security
intrusion-detection
security-tools
```

### Additional Optional Topics

```
threat-intelligence
siem
security-automation
blue-team
incident-response
log-parser
security-monitoring
vulnerability-detection
attack-detection
```

## Branch Protection Rules

Protect the `main` branch to maintain code quality and prevent accidental changes.

### Setting Up Branch Protection

1. Go to **Settings** → **Branches** → **Add branch protection rule**
2. Branch name pattern: `main`
3. Configure the following rules:

#### Required Settings

- ✅ **Require a pull request before merging**
  - Require approvals: `1`
  - Dismiss stale pull request approvals when new commits are pushed
  - Require review from Code Owners (if using CODEOWNERS file)

- ✅ **Require status checks to pass before merging**
  - Require branches to be up to date before merging
  - Status checks to require:
    - `test` (all Python versions)
    - `lint`
    - `format`
    - `type-check`
    - `integration`

- ✅ **Require conversation resolution before merging**

- ✅ **Require signed commits** (recommended but optional)

- ✅ **Include administrators** (apply rules to admins too)

#### Optional Settings

- ⚪ **Require linear history** (prevent merge commits)
- ⚪ **Require deployments to succeed** (if using environments)
- ⚪ **Lock branch** (prevent all pushes)

### Development Branch (Optional)

If using a `develop` branch:
1. Create similar protection rules
2. Allow more flexibility for experimental features
3. Set up automated merging from `develop` to `main` for releases

## GitHub Actions Secrets

Configure secrets for CI/CD workflows.

### Setting Up Secrets

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**

### Required Secrets

#### For PyPI Publishing

If using PyPI Trusted Publishers (recommended):
1. No secrets needed - uses OIDC authentication
2. Configure at https://pypi.org/manage/account/publishing/
3. Add trusted publisher for GitHub Actions

If using API tokens instead:
- `PYPI_API_TOKEN` - PyPI API token for publishing releases
- `TEST_PYPI_API_TOKEN` - Test PyPI token for testing releases

#### For Codecov (if not using GitHub App)

- `CODECOV_TOKEN` - Token from https://codecov.io/
  - Note: This is optional if repository is public

### Setting Up Environment Secrets

For better security, use environments:

1. Go to **Settings** → **Environments**
2. Create environments: `pypi`, `testpypi`
3. Add environment-specific secrets
4. Configure required reviewers for production

## GitHub Pages (Optional)

Host documentation using GitHub Pages.

### Setup Instructions

1. Go to **Settings** → **Pages**
2. Source: Deploy from a branch
3. Branch: `main` or `gh-pages`
4. Folder: `/docs` or `/ (root)`
5. Click **Save**

### Custom Domain (Optional)

1. Add a `CNAME` file with your domain
2. Configure DNS with your provider:
   ```
   CNAME: <your-domain> → shalbuzov.github.io
   ```
3. Enable **Enforce HTTPS** after DNS propagates

## Repository Settings

### General Settings

Navigate to **Settings** → **General**

#### Repository Details

- ✅ Description: "Professional automated web log reconnaissance and threat hunting tool"
- ✅ Website: Your documentation URL (if any)
- ✅ Topics: See [Topics section](#github-repository-topics)

#### Features

Enable/disable features:
- ✅ **Issues** - Enable for bug reports and feature requests
- ✅ **Discussions** - Enable for community Q&A
- ⚪ **Projects** - Optional (for roadmap tracking)
- ✅ **Wiki** - Optional (for extended documentation)
- ⚪ **Sponsorships** - Optional (if seeking sponsors)

#### Pull Requests

- ✅ **Allow squash merging** (recommended)
  - Default to pull request title
- ⚪ **Allow merge commits** (optional)
- ⚪ **Allow rebase merging** (optional)
- ✅ **Always suggest updating pull request branches**
- ✅ **Automatically delete head branches**

### Collaborators and Teams

1. Go to **Settings** → **Collaborators and teams**
2. Add collaborators with appropriate permissions:
   - **Admin** - Full access
   - **Maintain** - Can merge PRs and manage issues
   - **Write** - Can push to non-protected branches
   - **Triage** - Can manage issues and PRs
   - **Read** - Read-only access

### Webhooks and Integrations

Configure integrations:

1. Go to **Settings** → **Integrations**
2. Install GitHub Apps:
   - **Codecov** - Code coverage reporting
   - **pre-commit.ci** - Automated pre-commit checks
   - **Dependabot** - Security and dependency updates

## Third-Party Integrations

### Codecov Integration

1. Go to https://codecov.io/
2. Sign in with GitHub
3. Add repository: `shalbuzov/weblog-hunter`
4. Get the upload token (if private repo)
5. Add token as GitHub secret: `CODECOV_TOKEN`
6. Badge will be available at:
   ```markdown
   [![codecov](https://codecov.io/gh/shalbuzov/weblog-hunter/branch/main/graph/badge.svg)](https://codecov.io/gh/shalbuzov/weblog-hunter)
   ```

### Pre-commit.ci

1. Go to https://pre-commit.ci/
2. Sign in with GitHub
3. Enable for repository
4. Configuration is in `.pre-commit-config.yaml`
5. Auto-fixes will be pushed to PRs

### Dependabot

GitHub automatically enables Dependabot for security alerts.

#### Configuring Dependabot Updates

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "python"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "github-actions"
```

## Issue and PR Labels

Create consistent labels for organization:

### Go to Settings → Labels

#### Type Labels
- `bug` (🐛) - Something isn't working - `#d73a4a`
- `enhancement` (✨) - New feature or request - `#a2eeef`
- `documentation` (📝) - Documentation improvements - `#0075ca`
- `security` (🔒) - Security-related issues - `#d73a4a`

#### Priority Labels
- `priority: high` - `#d93f0b`
- `priority: medium` - `#fbca04`
- `priority: low` - `#0e8a16`

#### Status Labels
- `good first issue` - Good for newcomers - `#7057ff`
- `help wanted` - Extra attention needed - `#008672`
- `triage` - Needs triage - `#fef2c0`
- `wontfix` - This will not be worked on - `#ffffff`
- `duplicate` - This issue or PR already exists - `#cfd3d7`
- `invalid` - This doesn't seem right - `#e4e669`

#### Component Labels
- `parser` - Log parsing related - `#1d76db`
- `analyzer` - Threat analysis related - `#1d76db`
- `reporter` - Report generation related - `#1d76db`
- `cli` - Command-line interface - `#1d76db`

## Release Process

### Creating a Release

1. **Update Version**
   - Update version in `pyproject.toml`
   - Update `CHANGELOG.md`

2. **Commit and Push**
   ```bash
   git add pyproject.toml CHANGELOG.md
   git commit -m "chore: bump version to 2.1.0"
   git push origin main
   ```

3. **Create Git Tag**
   ```bash
   git tag -a v2.1.0 -m "Release v2.1.0"
   git push origin v2.1.0
   ```

4. **Create GitHub Release**
   - Go to **Releases** → **Draft a new release**
   - Choose tag: `v2.1.0`
   - Title: `v2.1.0 - Release Name`
   - Description: Copy from CHANGELOG.md
   - Check **Set as the latest release**
   - Click **Publish release**

5. **Automated Publishing**
   - GitHub Actions will automatically build and publish to PyPI
   - Monitor the workflow at Actions tab

## Monitoring and Analytics

### GitHub Insights

Regularly check:
- **Traffic** - Views and clones
- **Community** - Issues, PRs, discussions
- **Pulse** - Recent activity summary
- **Contributors** - Contribution statistics

### Setting Up Analytics (Optional)

Consider adding:
- **Google Analytics** (for GitHub Pages)
- **Plausible** (privacy-friendly alternative)

## Backup and Recovery

### Regular Backups

1. **Repository Backups**
   - GitHub automatically backs up your repository
   - Consider additional backups for critical data

2. **Settings Export**
   - Document all settings in this file
   - Export labels, workflows, and configurations

### Disaster Recovery

If repository becomes corrupted:
1. Contact GitHub Support
2. Restore from local clone
3. Use GitHub's import tool if needed

## Maintenance Checklist

### Weekly
- [ ] Review new issues and PRs
- [ ] Check CI/CD status
- [ ] Review Dependabot alerts

### Monthly
- [ ] Update dependencies
- [ ] Review and respond to discussions
- [ ] Update documentation
- [ ] Check code coverage trends

### Quarterly
- [ ] Review and update repository settings
- [ ] Audit collaborator permissions
- [ ] Review and close stale issues
- [ ] Update roadmap and milestones

## Getting Help

If you need help with repository setup:
- GitHub Docs: https://docs.github.com/
- GitHub Support: https://support.github.com/
- GitHub Community: https://github.community/

---

**Note**: This document should be kept up-to-date as the repository configuration evolves.
