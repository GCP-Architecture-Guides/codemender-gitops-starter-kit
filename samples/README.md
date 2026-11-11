# Vulnerable samples

> ⚠️ **These files are intentionally vulnerable.** They exist only to demonstrate CodeMender. Never
> deploy them or copy their patterns into real code. Every credential in them is a fake placeholder.

| File | Stack |
|---|---|
| `vulnerable_app.py` | Python (Flask + SQLite) |
| `vulnerable_app.go` | Go (`net/http` + SQLite) |
| `vulnerable_node.js` | Node.js (Express) |
| `VulnerableController.java` | Java (Spring) |
| `main.tf` | Terraform (Google Cloud) |

See [DEMO_GUIDE.md](../DEMO_GUIDE.md) for how to use them in a pull request. Files under `samples/`
are excluded from the container image (`.dockerignore`).
