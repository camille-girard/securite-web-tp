# Exam
## CI/CD Pipeline simple Python app

## Goal

Build a complete CI/CD pipeline for a simple Python application using GitHub Actions.

Your pipeline must:

1.  Run tests on multiple Python versions
2.  Run a Trivy vulnerability scan
3.  Build and push a Docker image to Docker Hub

I will provide a directory with a simple Python code. You can do your project on it, but won't get the best grade.

To get more points, feel free to take another vulnerable web application code or yours (implementation of a SQLi, Path Traversal etc), run the tests and CI/CD on it and implement the security measures related to what Trivy detected. 

## Step 1 —CI

Create a file called:

```
.github/workflows/ci.yml
```

Your CI pipeline must:

*   Be named “CI”
*   Run automatically on `push` on the `main` or `master` branch and with manual workflow trigger
*   Use the appropriate permissions on the `contents`, the `security-events` and the `actions`
*   Run on `ubuntu-latest` for both jobs

The first job will be called `test` and will have the following requirements:

*   Use a `matrix` strategy to test with Python version 3.8, 3.9, and 3.10
*   The first step will be named “checkout” and use `actions/checkout@v5`
*   The second step will be named “Python ${{ matrix.python-version }}” and use `actions/setup-python@v6`
*   The third step will be named “dependencies” and will install/upgrade pip, then install:
    *   `flake8` for code quality
    *   `pytest` for tests
*   The fourth step will be called “flake8”
    *   For flake8, the first run should:  
        *   Run on the current directory
        *   Count the number of errors
        *   Select the errors E9,F63,F7,F82 (check what these are)
        *   Show the source
        *   And display the statistics
    *   And for the second run:
        *   Run on the current directory
        *   Count the number of errors
        *   Return “0” even with errors
        *   And display the statistics
*   The fifth step will be called “pytest” and run tests on the `tests/` directory that I provided

The second job will be called `trivy-scan` and will have the following requirements:

*   The first step will be named “checkout” and will use `actions/checkout@v5` to retrieve our code
*   The second step will be named “trivy FS mode” and will use `aquasecurity/trivy-action@0.33.1` for a file system scan, in a sarif format named “results.sarif” for critical and high severity
*   The third step will be named “upload” and will use `github/codeql-action/upload-sarif@v4` with the previously generated sarif file

## Step 2 — CD

Create a file called:

```
.github/workflows/cd.yml
```

Your CD pipeline must:

*   Be named “CD”
*   Run automatically when your workflow “CI” is completed (check `workflow_run`)

The job will be named “build”,  use ubuntu-latest will have the following requirements:

*   Run only if the CI pipeline is successful
*   The first step will be named “checkout” and use `actions/checkout@v5`
*   The second step will be named “login” and use `docker/login-action@v3` with the following secrets

| Name | Description |
| --- | --- |
| `DOCKER_USERNAME` | Your Docker Hub username |
| `DOCKER_PASSWORD` | Your Docker Hub password or token |

In your GitHub project settings, "Actions secrets and variables", "Repository secrets" - Create a Personal access token in read and write on Docker Hub and link your credz to GitHub

*   The third step will be named “build and push” and use `docker/build-push-action@v6` with an id named “push”, the current directory context, the Dockerfile provided, the “push” defined to true and a tags (Be careful with the tags => put your username/xxx:latest)

## Step 3 — Test

1.  Push your code to GitHub
2.  Go to the Actions tab:
    *   Check that the CI pipeline runs and passes
    *   When it’s successful, verify that the CD pipeline runs
3.  Go to your Docker Hub account → Check the pushed image

## What to Submit

All this information will be in a .md file with the group members' name 

1.  Public GitHub repository URL
2.  Screenshot of CI pipeline passing in GitHub Actions
3.  Screenshot of CD pipeline passing
4.  Screenshot of your Docker Hub repository showing the image
5.  All the files you created (in blocks of code)

## Resources

*   [GitHub Actions Documentation](https://docs.github.com/en/actions)
*   [Pytest Documentation](https://docs.pytest.org/)
*   [Flake8 Documentation](https://flake8.pycqa.org/)
*   [Trivy GitHub Action](https://github.com/aquasecurity/trivy-action)
*   [Docker Build Push Action](https://github.com/docker/build-push-action)
