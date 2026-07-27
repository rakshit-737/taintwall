"""The mock environment the demo agent reads from and writes to."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class World:
    """Seedable mailbox, web pages, files, and secrets for one agent run."""

    emails: dict[str, str] = field(default_factory=dict)
    pages: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)

    @classmethod
    def seeded(
        cls,
        *,
        emails: dict[str, str] | None = None,
        pages: dict[str, str] | None = None,
        files: dict[str, str] | None = None,
        secrets: dict[str, str] | None = None,
    ) -> World:
        return cls(
            emails=dict(emails or {}),
            pages=dict(pages or {}),
            files=dict(files or {}),
            secrets=dict(secrets or {}),
        )

    def inject(self, *, channel: str, key: str, payload: str) -> None:
        """Splice an attack payload onto an existing carrier.

        The payload is appended to whatever the carrier already held, so a task's
        legitimate content still reads normally and the attack rides alongside it.
        """
        store = {"email": self.emails, "web": self.pages, "file": self.files}[channel]
        existing = store.get(key, "")
        store[key] = f"{existing}\n{payload}".strip()
