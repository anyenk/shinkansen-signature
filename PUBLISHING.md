# Publishing Guide

This document provides step-by-step instructions for publishing the `@anyenk/shinkansen-signature` library to GitHub and NPM.

## Prerequisites

### 1. GitHub Setup
- Ensure you have admin access to the `anyenk` GitHub organization
- Create the repository `shinkansen-signature` under the `anyenk` organization

### 2. NPM Setup
- Ensure you have an NPM account with publish permissions for the `@anyenk` scope
- Verify access with: `npm whoami`
- Login if needed: `npm login`

## Step-by-Step Publishing Process

### 1. Initialize Git Repository

```bash
cd /Users/ajunge/work/anyenk/shinkansen-signature
git init
git add .
git commit -m "Initial commit: Shinkansen signature library

🎉 Generated with Claude Code (https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

### 2. Create GitHub Repository

1. Go to [GitHub.com](https://github.com/orgs/anyenk/repositories)
2. Click "New repository"
3. Set repository name: `shinkansen-signature`
4. Description: "TypeScript library for creating and verifying Shinkansen JWS signatures"
5. Set to **Public**
6. Do NOT initialize with README (we already have one)
7. Click "Create repository"

### 3. Connect Local Repository to GitHub

```bash
git remote add origin https://github.com/anyenk/shinkansen-signature.git
git branch -M main
git push -u origin main
```

### 4. Set up GitHub Secrets for NPM Publishing

1. Go to repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `NPM_TOKEN`
4. Value: Your NPM automation token (create at https://www.npmjs.com/settings/tokens)
   - Choose "Automation" type token
   - Copy the token value

### 5. Pre-publish Verification

```bash
# Run all quality checks
npm test
npm run build
npm run lint
npm run typecheck

# Test the package locally
npm pack
# This creates a .tgz file you can inspect
```

### 6. Publish to NPM

#### Option A: Manual Publishing
```bash
# For scoped packages, you need to specify public access
npm publish --access public

# Or use the convenience script
npm run publish:public
```

#### Option B: Automated Publishing via GitHub Release
1. Go to GitHub repository → Releases
2. Click "Create a new release"
3. Tag version: `v1.0.0`
4. Release title: `v1.0.0 - Initial Release`
5. Description:
   ```markdown
   🎉 Initial release of @anyenk/shinkansen-signature
   
   ## Features
   - Create and verify Shinkansen JWS signatures
   - PS256 algorithm support with detached signatures
   - X.509 certificate validation
   - Full TypeScript support
   - Comprehensive test suite
   
   ## Installation
   ```bash
   npm install @anyenk/shinkansen-signature
   ```
   ```
6. Click "Publish release"
   - This will trigger the GitHub Action to automatically publish to NPM

### 7. Verify Publication

```bash
# Check NPM
npm view @anyenk/shinkansen-signature

# Test installation in a new directory
mkdir test-install
cd test-install
npm init -y
npm install @anyenk/shinkansen-signature
```

## Post-Publication Tasks

### 1. Update README Badge
Add build status badge to README.md:
```markdown
[![CI](https://github.com/anyenk/shinkansen-signature/actions/workflows/ci.yml/badge.svg)](https://github.com/anyenk/shinkansen-signature/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/%40anyenk%2Fshinkansen-signature.svg)](https://badge.fury.io/js/%40anyenk%2Fshinkansen-signature)
```

### 2. Create GitHub Issue Templates
Create `.github/ISSUE_TEMPLATE/` with templates for bugs and features.

### 3. Set up Branch Protection
1. Go to Settings → Branches
2. Add rule for `main` branch
3. Require status checks (CI workflow)
4. Require pull request reviews

## Version Management

### Semantic Versioning
- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (1.0.0 → 1.1.0): New features, backward compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes, backward compatible

### Publishing New Versions
```bash
# Update version
npm version patch  # or minor, major

# Push with tags
git push origin main --tags

# Create GitHub release for automated publishing
# OR manually publish:
npm publish
```

## Security Considerations

1. **NPM Token**: Use automation tokens, not personal tokens
2. **Two-Factor Authentication**: Enable 2FA on NPM account
3. **Repository Access**: Limit who can push to main branch
4. **Dependency Security**: Run `npm audit` regularly
5. **Code Signing**: Consider signing releases

## Troubleshooting

### Common Issues

1. **403 Forbidden on NPM publish**
   - Check NPM token permissions
   - Verify scope access for `@anyenk`

2. **GitHub Action fails**
   - Check NPM_TOKEN secret is set correctly
   - Verify workflow permissions

3. **Build failures**
   - Run `npm ci` instead of `npm install`
   - Check Node.js version compatibility

### Getting Help
- NPM issues: https://github.com/npm/cli/issues
- GitHub Actions: https://github.com/actions/setup-node/issues
- Library issues: Create issue in repository