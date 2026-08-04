# Contributing to NetInsight-X

Thank you for contributing to NetInsight-X! To maintain corporate-level software standards, please review the guidelines below before opening pull requests.

---

## 1. Development Standards

*   **Python Formatting:** We adhere strictly to PEP 8 style formatting. Code is automatically linted using **Ruff**. Line limits are set to `120` characters.
*   **Go Formatting:** Go source code must be formatted using `gofmt` before committing.
*   **Editor Standardization:** Ensure your IDE supports [EditorConfig](.editorconfig) to automatically enforce indentation and spacing rules.

---

## 2. Commit Message Guidelines

We follow the **Conventional Commits** standard. Commit messages must be structured as follows:

```text
<type>[optional scope]: <description>

[optional body]
```

### Supported Types:
*   `feat`: A new feature (e.g., `feat(agent): implement disk-buffered offline queue`)
*   `fix`: A bug fix (e.g., `fix(shaper): resolve permission handler crash on windows`)
*   `docs`: Documentation changes
*   `style`: Code formatting changes (whitespaces, semi-colons, etc.)
*   `refactor`: Code restructuring without modifying behavior
*   `test`: Adding or modifying unit tests

---

## 3. Pull Request Process

1.  **Branch Naming:** Create branches starting with prefixes:
    *   `feature/feature-name`
    *   `bugfix/issue-name`
    *   `chore/maintenance-task`
2.  **Linting & Testing:** Run lint checks and the test suite locally before pushing:
    ```bash
    ruff check .
    python manage.py test
    ```
3.  **CI Checks:** Ensure the GitHub Actions Continuous Integration (CI) checks pass completely. Pull requests with failing CI steps will not be merged.
