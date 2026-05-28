# Publishing to PyPI

This guide outlines how `agent-guardian` is built and published to PyPI using **Trusted Publishing (OIDC)** and GitHub Actions.

---

## Overview
Releases are built and published automatically via the GitHub Actions workflow defined in [publish.yml](file:///Users/mobionix/workspace/Glacien/guardian-oss/.github/workflows/publish.yml) whenever a release tag is pushed to GitHub.

---

## 1. Setup on PyPI (One-Time Setup)
We use PyPI's **Trusted Publishing (OIDC)**, which allows GitHub Actions to securely authenticate and upload packages to PyPI without managing passwords, API keys, or long-lived secrets.

To configure OIDC for `agent-guardian`:
1. Log into your account on [PyPI](https://pypi.org/).
2. Navigate to **Account Settings** > **Publishing**.
3. Under **Add a publisher**, select **GitHub**.
4. Fill in the following exact details:
   * **PyPI Project Name**: `agent-guardian`
   * **Owner**: `glacien-technologies`
   * **Repository name**: `agent-guardian`
   * **Workflow name**: `publish.yml`
   * **Environment name**: `pypi`
5. Click **Add** to register the pending publisher.

---

## 2. Triggering a Release
To publish a new version of the package to PyPI, follow these steps:

### Step 1: Update the Version Number
The package version is defined in the version file. Update the version string in:
* [src/agent_guardian/_version.py](file:///Users/mobionix/workspace/Glacien/guardian-oss/src/agent_guardian/_version.py)

Example:
```python
__version__ = "1.0.0rc1"
```

### Step 2: Ensure Changes are Committed & Pushed
Any local changes must be committed and pushed to the `main` branch on GitHub before tagging. The GitHub Action builds directly from the pushed commit on GitHub, not from your local workspace.

```bash
git add .
git commit -s -m "release: bump version to 1.0.0rc1"
git push origin main
```

### Step 3: Tag and Push the Release
Create a matching git tag with a `v` prefix and push it. This triggers the GitHub publishing action.

```bash
# Create the local tag (matching the version in _version.py)
git tag v1.0.0rc1

# Push the tag to GitHub
git push origin v1.0.0rc1
```

---

## 3. Monitoring the Release
Once you push the tag:
1. Go to the **Actions** tab of the `glacien-technologies/agent-guardian` repository on GitHub.
2. Select the running **Publish to PyPI** workflow run.
3. Once the workflow completes, the release will be live on [PyPI](https://pypi.org/project/agent-guardian/).

To install the published package:
```bash
pip install agent-guardian==1.0.0rc1
```
