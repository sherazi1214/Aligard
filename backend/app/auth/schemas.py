"""Request bodies. Extra fields reject, lengths capped."""
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, StringConstraints

Password = Annotated[str, StringConstraints(min_length=1, max_length=256)]
Token = Annotated[str, StringConstraints(min_length=10, max_length=200)]
Code = Annotated[str, StringConstraints(min_length=6, max_length=16)]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmailBody(_Base):
    email: EmailStr


class SignupBody(_Base):
    email: EmailStr
    password: Password


class LoginBody(_Base):
    email: EmailStr
    password: Password


class TokenBody(_Base):
    token: Token


class ResetBody(_Base):
    token: Token
    password: Password


class MfaBody(_Base):
    code: Code


class ChangePasswordBody(_Base):
    current_password: Password
    new_password: Password


class DisableTotpBody(_Base):
    password: Password
    code: Code
