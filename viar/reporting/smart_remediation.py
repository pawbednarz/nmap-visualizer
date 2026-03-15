"""
Smart Remediation generator.

Produces language-specific code fix snippets tailored to the tech stack
detected from Burp response headers (Server, X-Powered-By, etc.).
"""
from __future__ import annotations

import logging
import re
from typing import Any

from viar.models.finding import SecurityFinding, VulnCategory
from viar.models.report import RemediationSnippet

logger = logging.getLogger(__name__)

# Maps detected tech fingerprints to primary language/framework
_TECH_LANGUAGE_MAP: dict[str, tuple[str, str]] = {
    "asp.net": ("csharp", "ASP.NET"),
    "php": ("php", "PHP"),
    "java": ("java", "Java/Spring"),
    "spring": ("java", "Java/Spring"),
    "django": ("python", "Python/Django"),
    "flask": ("python", "Python/Flask"),
    "express": ("javascript", "Node.js/Express"),
    "rails": ("ruby", "Ruby on Rails"),
    "laravel": ("php", "PHP/Laravel"),
    "go": ("go", "Go"),
}

# Language-specific fix templates
_FIX_TEMPLATES: dict[VulnCategory, dict[str, str]] = {
    VulnCategory.SQLI: {
        "python": '''# VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# FIXED — use parameterised queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))''',
        "java": '''// VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;
stmt = conn.createStatement();
stmt.executeQuery(query);

// FIXED — use PreparedStatement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
ps.setInt(1, userId);
ps.executeQuery();''',
        "php": '''// VULNERABLE
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// FIXED — use prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);''',
        "go": '''// VULNERABLE
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
db.Query(query)

// FIXED — use parameterised query
db.QueryRow("SELECT * FROM users WHERE id = $1", userID)''',
    },
    VulnCategory.XSS: {
        "python": '''# VULNERABLE (Flask — unescaped output)
return f"<h1>Hello, {username}</h1>"

# FIXED — use Jinja2 auto-escaping (enabled by default in Flask)
# In template: <h1>Hello, {{ username }}</h1>
# Explicitly escape if needed:
from markupsafe import escape
return f"<h1>Hello, {escape(username)}</h1>"''',
        "java": '''// VULNERABLE
response.getWriter().write("<h1>Hello, " + username + "</h1>");

// FIXED — use OWASP Java Encoder
import org.owasp.encoder.Encode;
response.getWriter().write(
    "<h1>Hello, " + Encode.forHtml(username) + "</h1>"
);''',
        "javascript": '''// VULNERABLE (DOM XSS)
element.innerHTML = userInput;

// FIXED — use textContent
element.textContent = userInput;
// Or use DOMPurify for rich content
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);''',
    },
    VulnCategory.IDOR: {
        "python": '''# VULNERABLE — trusts user-supplied ID
@app.route("/document/<int:doc_id>")
def get_document(doc_id):
    return Document.query.get(doc_id)

# FIXED — enforce ownership check
@app.route("/document/<int:doc_id>")
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(
        id=doc_id, owner_id=current_user.id
    ).first_or_404()
    return doc''',
        "java": '''// VULNERABLE
@GetMapping("/document/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
}

// FIXED — enforce ownership at repository level
@GetMapping("/document/{id}")
public Document getDocument(@PathVariable Long id, @AuthenticationPrincipal User user) {
    return documentRepository.findByIdAndOwner(id, user)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.FORBIDDEN));
}''',
    },
    VulnCategory.BAC: {
        "python": '''# FIXED — decorator-based role enforcement (Flask-Login example)
from functools import wraps
from flask_login import current_user
from flask import abort

def requires_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.has_role(role):
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/admin/users")
@login_required
@requires_role("admin")
def admin_users():
    return User.query.all()''',
        "java": '''// FIXED — Spring Security method-level security
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> getUsers() {
    return userService.findAll();
}''',
    },
}


class SmartRemediationGenerator:
    """
    Generates technology-aware code remediation snippets.

    Detects the target tech stack from Burp fingerprints and selects
    the most relevant code example in that language.
    """

    def __init__(self, llm_client: Any, model: str = "claude-sonnet-4-6"):
        self.llm = llm_client
        self.model = model

    def generate(
        self,
        finding: SecurityFinding,
        tech_fingerprints: list[str],
    ) -> list[RemediationSnippet]:
        """Generate code fix snippets for a finding, adapted to the detected stack."""
        language, framework = self._detect_language(tech_fingerprints)
        snippets: list[RemediationSnippet] = []

        # Try template-based snippet first
        template_snippet = self._from_template(finding, language, framework)
        if template_snippet:
            snippets.append(template_snippet)

        # LLM-generated snippet for additional context or missing templates
        if not snippets or finding.category not in _FIX_TEMPLATES:
            llm_snippet = self._from_llm(finding, language, framework)
            if llm_snippet:
                snippets.append(llm_snippet)

        return snippets

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _detect_language(
        self, fingerprints: list[str]
    ) -> tuple[str, str]:
        """Map detected tech fingerprints to (language, framework)."""
        combined = " ".join(fingerprints).lower()
        for keyword, (lang, framework) in _TECH_LANGUAGE_MAP.items():
            if keyword in combined:
                return lang, framework
        return "python", "Generic"

    def _from_template(
        self,
        finding: SecurityFinding,
        language: str,
        framework: str,
    ) -> RemediationSnippet | None:
        category_templates = _FIX_TEMPLATES.get(finding.category)
        if not category_templates:
            return None

        code = category_templates.get(language) or category_templates.get("python")
        if not code:
            return None

        # Build a simple diff
        lines = code.splitlines()
        vulnerable = "\n".join(l for l in lines if "VULNERABLE" in l or (l and not l.startswith("#") and lines.index(l) < len(lines) // 2))
        fixed = "\n".join(l for l in lines if "FIXED" in l or (l and not l.startswith("#") and lines.index(l) >= len(lines) // 2))

        return RemediationSnippet(
            finding_id=finding.finding_id,
            language=language,
            framework=framework,
            description=f"Fix for {finding.title} in {framework}",
            vulnerable_code=vulnerable,
            fixed_code=code,
        )

    def _from_llm(
        self,
        finding: SecurityFinding,
        language: str,
        framework: str,
    ) -> RemediationSnippet | None:
        prompt = (
            f"You are a senior {framework} developer fixing a security vulnerability.\n\n"
            f"Vulnerability: {finding.title}\n"
            f"Category: {finding.category.value}\n"
            f"Affected URL: {finding.affected_url}\n"
            f"Technical Description: {finding.technical_description[:400]}\n\n"
            f"Write a concise {language} code snippet showing:\n"
            "1. The VULNERABLE pattern (commented as '# VULNERABLE' or '// VULNERABLE')\n"
            "2. The FIXED version (commented as '# FIXED' or '// FIXED')\n"
            "Include only the code block, no explanation. Use real, production-quality code."
        )

        try:
            response = self.llm.invoke([{"role": "user", "content": prompt}])
            text = response.content if hasattr(response, "content") else str(response)
            code = self._extract_code_block(text)
            if not code:
                return None
            return RemediationSnippet(
                finding_id=finding.finding_id,
                language=language,
                framework=framework,
                description=f"AI-generated fix for {finding.title} in {framework}",
                fixed_code=code,
            )
        except Exception as exc:
            logger.warning("LLM remediation generation failed: %s", exc)
            return None

    def _extract_code_block(self, text: str) -> str | None:
        """Extract content of first fenced code block."""
        match = re.search(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
        return match.group(1).strip() if match else text.strip()[:2000] or None
