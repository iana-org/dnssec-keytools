"""Config validation schema."""

from pathlib import Path
from typing import Annotated, Any, Mapping, Self

from pydantic import BaseModel, EmailStr, Field, FilePath

from kskm.common.config_misc import HexDigestString


class WKSR_TLS(BaseModel):
    cert: FilePath
    key: FilePath
    ca_cert: FilePath
    ciphers: list[str] = Field(
        default_factory=lambda: [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-SHA384",
        ]
    )  # TODO: could be a colon-separated string too before
    require_client_cert: bool
    client_whitelist: list[HexDigestString] = Field(default_factory=list)


class WKSR_KSR(BaseModel):
    max_size: Annotated[int, Field(gt=0, default=1024 * 1024)]
    content_type: str = "application/xml"
    prefix: Path = Path("upload_")
    ksrsigner_configfile: FilePath


class WKSR_Templates(BaseModel):
    upload: FilePath
    result: FilePath
    email: FilePath

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Instantiate templates from a dict."""
        return cls.model_validate(data)


class WKSR_Notify(BaseModel):
    from_: EmailStr = Field(alias="from")
    to: EmailStr
    subject: str
    smtp_server: str


class WKSR_Config(BaseModel):
    tls: WKSR_TLS
    ksr: WKSR_KSR
    templates: WKSR_Templates
    notify: WKSR_Notify | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Instantiate configuration from a dict."""
        return cls.model_validate(data)
