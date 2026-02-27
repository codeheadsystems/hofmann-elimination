# Release Process

This document describes how to create a new release of PretenderDB.

## Prerequisites

Before creating your first release, ensure you have:

1. **Maven Central Account**: Account at https://central.sonatype.com with verified namespace for `io.github.pretenderdb`
2. **GPG Key**: GPG key for signing artifacts, published to public keyservers
3. **GitHub Secrets**: Five secrets configured in the repository settings

## One-Time Setup

### 1. Maven Central Account Setup (New Portal Method - 2024+)

**Note:** As of 2024, Sonatype uses the Central Portal instead of the old JIRA-based system.

1. **Register an Account**
   - Visit https://central.sonatype.com
   - Click "Sign In" in the top right
   - Choose authentication method:
     - **Recommended:** Sign in with GitHub (provides automatic namespace verification)
     - Alternative: Create username/password account
   - Provide a valid email address (required for support and notifications)

2. **Verify Namespace for `io.github.pretenderdb`**

   **For GitHub Organization namespaces:**
   - Currently, `io.github.<organization-name>` namespaces are not automatically available
   - You must contact Maven Central Support to request the namespace
   - Email Central Support at: https://central.sonatype.org/support
   - Provide:
     - Desired namespace: `io.github.pretenderdb`
     - GitHub organization: https://github.com/PretenderDB
     - Proof of ownership (you are an owner/admin of the PretenderDB organization)
   - They may provide a verification key and ask you to create a temporary public repository

   **Alternative (if using personal account):**
   - If you sign in with your personal GitHub account, `io.github.<your-username>` is auto-verified
   - However, this won't match the `io.github.pretenderdb` namespace

3. **Generate User Token**
   - Once your namespace is verified, visit https://central.sonatype.com
   - Navigate to your Account page
   - Click "Generate User Token"
   - Save the generated **username** and **password** (this is your publishing token, not your login password)
   - You'll use these credentials for Gradle/Maven publishing

**Important Notes:**
- The user token is different from your login credentials
- These tokens are used specifically for publishing via API/build tools
- Keep your token secure - treat it like a password

### 2. GPG Key Setup

Generate a GPG key if you don't have one:

```bash
# Generate key (choose RSA and RSA, 4096 bits)
gpg --gen-key

# List keys to get the key ID
gpg --list-secret-keys --keyid-format=long
# Output shows: sec rsa4096/ABCD1234EFGH5678 ...
# The key ID is: ABCD1234EFGH5678

# Export private key for GitHub secrets (base64 encoded)
gpg --export-secret-keys YOUR_KEY_ID | base64 -w 0 > private-key.txt

# Publish public key to keyservers (required for Maven Central)
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
gpg --keyserver keys.openpgp.org --send-keys YOUR_KEY_ID

# Verify key was published
gpg --keyserver keyserver.ubuntu.com --recv-keys YOUR_KEY_ID
```

### 3. Configure GitHub Secrets

Navigate to: https://github.com/PretenderDB/PretenderDB/settings/secrets/actions

Add the following secrets:

| Secret Name | Value | Description |
|-------------|-------|-------------|
| `CENTRAL_PORTAL_USERNAME` | User token username | Username from "Generate User Token" (NOT your login username) |
| `CENTRAL_PORTAL_PASSWORD` | User token password | Password from "Generate User Token" (NOT your login password) |
| `GPG_PRIVATE_KEY` | Content of private-key.txt | Base64-encoded GPG private key |
| `GPG_PASSPHRASE` | Your GPG key passphrase | Passphrase for the GPG key |
| `GPG_KEY_ID` | Last 8 chars of key ID | Short key ID (e.g., EFGH5678) |

**Security Notes:**
- `CENTRAL_PORTAL_USERNAME` and `CENTRAL_PORTAL_PASSWORD` are the **user token credentials** from https://central.sonatype.com, not your portal login credentials
- Store the GPG key passphrase securely
- Delete `private-key.txt` after uploading to GitHub secrets
- Never commit credentials to the repository

## Creating a Release

### Step 1: Prepare Release

1. Ensure the `main` branch is clean and all tests pass:

```bash
git checkout main
git pull
./gradlew clean build test
```

2. Review changes since last release:

```bash
# List changes since last tag
git log --oneline v1.0.0..HEAD  # Replace v1.0.0 with last tag

# Or if this is the first release
git log --oneline
```

3. Update documentation if needed:
   - README.md
   - CHANGELOG.md (if you maintain one)
   - IMPLEMENTATION_SUMMARY.md

### Step 2: Create and Push Tag

1. Create a semantic version tag:

```bash
# For a regular release
git tag -a v1.0.0 -m "Release version 1.0.0"

# For a pre-release (RC, beta, alpha)
git tag -a v1.0.0-rc.1 -m "Release candidate 1.0.0-rc.1"
```

2. Push the tag to GitHub:

```bash
git push origin v1.0.0
```

3. The GitHub Actions workflow will automatically:
   - Validate the tag format (must match `vX.Y.Z` or `vX.Y.Z-suffix`)
   - Extract the version from the tag
   - Build and test all modules
   - Sign artifacts with GPG
   - Publish to Maven Central via Central Portal
   - Automatically release the deployment
   - Create a GitHub release with JAR artifacts

### Step 3: Monitor Release

1. Watch the GitHub Actions workflow at:
   - https://github.com/PretenderDB/PretenderDB/actions

2. The workflow takes approximately 10-15 minutes to complete

3. If successful:
   - GitHub release will be created at: https://github.com/PretenderDB/PretenderDB/releases
   - Artifacts will be available in Maven Central within 15-120 minutes
   - Pre-release flag will be set automatically for tags with suffixes

### Step 4: Verify Publication

1. Check GitHub release:
   - https://github.com/PretenderDB/PretenderDB/releases/tag/v1.0.0

2. Verify Maven Central (wait 15-120 minutes after release):
   - https://repo1.maven.org/maven2/io/github/pretenderdb/
   - Check that both published modules are present with correct version:
     - `database-utils`
     - `pretender`

3. Test downloading the artifacts:

```bash
# Create a test project
mkdir /tmp/test-pretenderdb && cd /tmp/test-pretenderdb

# Create minimal build.gradle.kts
cat > build.gradle.kts << 'EOF'
plugins {
    java
}
repositories {
    mavenCentral()
}
dependencies {
    implementation("io.github.pretenderdb:pretender:1.0.0")
}
EOF

# Try to resolve
gradle dependencies --configuration runtimeClasspath
```

### Step 5: Post-Release

1. Announce the release (optional):
   - Social media
   - Mailing lists
   - Discussion forums

2. Update project status badges if applicable

## Version Strategy

PretenderDB follows [Semantic Versioning](https://semver.org/):

- **Major (X.0.0)**: Breaking API changes, incompatible changes
- **Minor (1.X.0)**: New features, backward-compatible additions
- **Patch (1.0.X)**: Bug fixes, backward-compatible fixes
- **Pre-release (1.0.0-rc.1)**: Release candidates, alphas, betas

Examples:
- `v1.0.0` - First stable release
- `v1.1.0` - Added new features
- `v1.1.1` - Bug fix
- `v2.0.0` - Breaking changes
- `v1.2.0-rc.1` - Release candidate

**Both published modules share the same version number.**

Note: The `pretender-integ` module is for integration testing only and is not published to Maven Central.

## Troubleshooting

### Release Failed: GPG Signing Error

**Symptoms:**
- Error message: "gpg: signing failed: No secret key"
- Error message: "gpg: signing failed: Inappropriate ioctl for device"

**Solutions:**
1. Verify `GPG_PRIVATE_KEY` secret is correct (must be base64 encoded)
2. Verify `GPG_PASSPHRASE` is correct
3. Verify `GPG_KEY_ID` matches the key in the private key
4. Ensure GPG public key is published to keyservers:
   ```bash
   gpg --keyserver keyserver.ubuntu.com --recv-keys YOUR_KEY_ID
   ```

### Release Failed: Maven Central Authentication

**Symptoms:**
- HTTP 401 Unauthorized
- "Could not authenticate" errors
- Authentication failures during publishing

**Solutions:**
1. Verify `CENTRAL_PORTAL_USERNAME` and `CENTRAL_PORTAL_PASSWORD` secrets contain the **user token credentials** (not your login credentials)
2. Regenerate user token at https://central.sonatype.com (Account page → Generate User Token)
3. Check your namespace `io.github.pretenderdb` is verified in Central Portal
4. Verify account has publishing rights for `io.github.pretenderdb` namespace
5. Try logging into https://central.sonatype.com to confirm your account is active

### Release Failed: Version Mismatch

**Symptoms:**
- Error: "Gradle version does not match tag version"

**Solutions:**
1. Ensure tag format is exactly `vX.Y.Z` (e.g., `v1.0.0`)
2. Check that `git describe --tags --exact-match HEAD` works locally:
   ```bash
   git tag v1.0.0
   git describe --tags --exact-match HEAD  # Should output: v1.0.0
   ```

### Release Failed: Tests Failed

**Symptoms:**
- Build failed during test phase

**Solutions:**
1. Run tests locally before tagging:
   ```bash
   ./gradlew clean build test
   ```
2. Fix any failing tests
3. Delete the tag and re-tag after fixes:
   ```bash
   git tag -d v1.0.0
   git push --delete origin v1.0.0
   # Fix issues, then re-tag
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

### Release Failed: Central Portal Validation

**Symptoms:**
- Deployment fails validation on Central Portal
- Missing POM information or signatures

**Solutions:**
1. Check POM files are generated correctly:
   ```bash
   ./gradlew generatePomFileForMavenJavaPublication
   find . -name "pom-default.xml" -exec cat {} \;
   ```
2. Verify signing is working locally:
   ```bash
   ./gradlew signMavenJavaPublication
   find . -name "*.asc"
   ```
3. Check deployment status at https://central.sonatype.com under "Deployments"

### Manual Release Recovery

If the automated release fails after artifacts are uploaded:

1. Log into https://central.sonatype.com
2. Navigate to "Deployments" in the left sidebar
3. Find your deployment (check status: Published, Failed, Pending, or Validated)
4. Review any validation errors
5. If validation passed but not published:
   - The nmcp plugin should have auto-published
   - Contact Central Support if stuck
6. If validation failed:
   - Note the errors
   - Fix issues locally
   - Delete the Git tag: `git push --delete origin v1.0.0`
   - Re-run the release after fixes

**Note:** The nmcp Gradle plugin handles the Central Portal publishing API automatically.

### Rollback a Release

**Important:** You cannot unpublish from Maven Central. Once released, artifacts are permanent.

If you need to fix a released version:

1. **For critical bugs:** Release a patch version (e.g., v1.0.1)
2. **For breaking issues:** Mark the version as problematic in release notes
3. **For security issues:** Release a hotfix immediately (e.g., v1.0.0-hotfix.1 or v1.0.1)

To mark a GitHub release as problematic:
1. Edit the release at https://github.com/PretenderDB/PretenderDB/releases
2. Check "Set as a pre-release" or add a warning to the description
3. Create a new release with fixes

## Testing Locally

Before creating a production release, test the configuration locally:

### Test Version Extraction

```bash
# Create a test tag
git tag -a v0.1.0-test -m "Test tag"

# Verify version is extracted
./gradlew properties | grep "^version:"
# Should show: version: 0.1.0-test

# Remove test tag
git tag -d v0.1.0-test
```

### Test Publication Configuration

```bash
# Verify configuration
./gradlew verifyPublishConfig

# Expected output:
# Group: io.github.pretenderdb
# Artifact: pretender (or database-utils, pretender-integ)
# Version: 0.0.1-SNAPSHOT
# Is SNAPSHOT: true
# Repository: snapshots
```

### Test Local Publishing

```bash
# Build and publish to local Maven repository
./gradlew clean build publishToMavenLocal

# Verify artifacts in ~/.m2/repository
ls -R ~/.m2/repository/io/github/pretenderdb/

# Expected structure:
# ~/.m2/repository/io/github/pretenderdb/
# ├── database-utils/
# ├── pretender/
# └── pretender-integ/
```

### Test Signing (Requires GPG Setup)

```bash
# Configure GPG locally in ~/.gradle/gradle.properties:
cat >> ~/.gradle/gradle.properties << EOF
signing.gnupg.keyName=YOUR_KEY_ID
signing.gnupg.passphrase=YOUR_PASSPHRASE
EOF

# Test signing
./gradlew signMavenJavaPublication

# Check for signature files
find . -name "*.asc"
```

## Dry-Run Release (Optional)

For additional safety, you can create a manual dry-run workflow:

1. Go to: https://github.com/PretenderDB/PretenderDB/actions
2. Run "Release Dry Run" workflow (if implemented)
3. Provide a test version like `0.0.1-dryrun`
4. Verify the build completes successfully

This tests the build and artifact generation without publishing.

## Release Checklist

Use this checklist when creating a release:

- [ ] All tests pass locally: `./gradlew clean build test`
- [ ] Documentation is up to date (README, CLAUDE.md, etc.)
- [ ] Changes reviewed and ready for release
- [ ] Semantic version chosen appropriately
- [ ] Tag created with correct format: `vX.Y.Z`
- [ ] Tag pushed to GitHub
- [ ] GitHub Actions workflow succeeded
- [ ] GitHub release created
- [ ] Artifacts available in Maven Central (wait 15-120 minutes)
- [ ] Artifacts downloadable and usable
- [ ] Release announced (if applicable)

## FAQ

### How do I know which version number to use?

Follow semantic versioning:
- Breaking changes → increment major (2.0.0)
- New features → increment minor (1.1.0)
- Bug fixes → increment patch (1.0.1)

### Can I publish SNAPSHOT versions?

**Automatic:** SNAPSHOT versions are automatically published when pushing to the `main` branch. The `snapshot.yml` workflow handles this.

**Manual:** You can also publish snapshots manually:
```bash
./gradlew publishAggregationToCentralSnapshots
```

Snapshots are available at:
- https://central.sonatype.com/repository/maven-snapshots/io/github/pretenderdb/

Users can depend on SNAPSHOT versions by adding the snapshots repository:
```kotlin
repositories {
    maven("https://central.sonatype.com/repository/maven-snapshots/")
    mavenCentral()
}

dependencies {
    implementation("io.github.pretenderdb:pretender:0.0.1-SNAPSHOT")
}
```

### How long does it take for artifacts to appear in Maven Central?

Typically 15-30 minutes, but can take up to 2 hours. The CDN and search index update separately.

### What if I create a tag by mistake?

Delete the tag before the workflow completes:

```bash
# Delete local tag
git tag -d v1.0.0

# Delete remote tag
git push --delete origin v1.0.0
```

If the workflow already completed, you cannot unpublish from Maven Central. Create a new patch version instead.

### Can I automate releases further?

Yes, you could add:
- Automatic version bumping based on commit messages
- Changelog generation
- Release notes templates
- Slack/Discord notifications

However, manual tagging provides more control and prevents accidental releases.

## Support

For questions or issues with releases:
- Create an issue: https://github.com/PretenderDB/PretenderDB/issues
- Contact: ned.wolpert@gmail.com
