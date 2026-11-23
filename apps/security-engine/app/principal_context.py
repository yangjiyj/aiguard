"""Strict trusted principal context received from internal gateway callers."""

from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class PrincipalContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1]
    tenant_id: str
    actor_user_id: str = ""
    key_owner_user_id: str = ""
    actor_department_ids: List[str] = Field(default_factory=list)
    actor_department_ancestor_ids: List[str] = Field(default_factory=list)
    key_owner_department_ids: List[str] = Field(default_factory=list)
    key_owner_department_ancestor_ids: List[str] = Field(default_factory=list)
    project_id: str = ""
    application_id: str = ""
    application_department_id: str = ""
    key_id: str = ""
    protocol: str = ""
    entry_point: str = ""
    model_id: str = ""
    identity_source: Literal["unknown", "api_key", "forward_proxy", "reverse_proxy", "session"]
    trust_level: Literal["unknown", "key_bound", "authenticated"]
    identity_version: str = ""

    @field_validator(
        "tenant_id", "actor_user_id", "key_owner_user_id", "project_id",
        "application_id", "application_department_id", "key_id", "protocol",
        "entry_point", "identity_version", "model_id",
    )
    @classmethod
    def canonical_scalar(cls, value: str, info) -> str:
        if value != value.strip() or len(value) > 256 or any(ord(ch) < 32 for ch in value):
            raise ValueError(f"{info.field_name} is not canonical")
        if info.field_name == "tenant_id" and not value:
            raise ValueError("tenant_id is required")
        if info.field_name in {"protocol", "entry_point"} and value != value.lower():
            raise ValueError(f"{info.field_name} must be lowercase")
        if info.field_name in {"protocol", "entry_point"} and value and not all(
            ch.isascii() and (ch.islower() or ch.isdigit() or ch in "_.:-") for ch in value
        ):
            raise ValueError(f"{info.field_name} is invalid")
        return value

    @field_validator(
        "actor_department_ids", "actor_department_ancestor_ids",
        "key_owner_department_ids", "key_owner_department_ancestor_ids",
    )
    @classmethod
    def canonical_ids(cls, values: List[str], info) -> List[str]:
        if any(not value or value != value.strip() or len(value) > 256 for value in values):
            raise ValueError(f"{info.field_name} contains an invalid identity")
        if values != sorted(set(values)):
            raise ValueError(f"{info.field_name} must be sorted and unique")
        return values

    @model_validator(mode="after")
    def valid_trust_contract(self):
        if self.project_id != self.application_id:
            raise ValueError("project and application identity conflict")
        if self.trust_level == "unknown" and any((
            self.actor_user_id, self.key_owner_user_id,
            self.actor_department_ids, self.actor_department_ancestor_ids,
            self.key_owner_department_ids, self.key_owner_department_ancestor_ids,
        )):
            raise ValueError("unknown principal cannot carry user identity")
        if self.trust_level == "key_bound":
            if not self.key_id or self.actor_user_id or self.actor_department_ids or self.actor_department_ancestor_ids:
                raise ValueError("key-bound principal contract is invalid")
        if self.trust_level == "authenticated" and not self.actor_user_id:
            raise ValueError("authenticated principal requires actor")
        if (self.actor_department_ids or self.actor_department_ancestor_ids) and not self.actor_user_id:
            raise ValueError("actor departments require actor")
        if (self.key_owner_department_ids or self.key_owner_department_ancestor_ids) and not self.key_owner_user_id:
            raise ValueError("key owner departments require key owner")
        if self.key_owner_user_id and not self.key_id:
            raise ValueError("key owner requires key identity")
        if self.application_department_id and not self.application_id:
            raise ValueError("application department requires application")
        return self
