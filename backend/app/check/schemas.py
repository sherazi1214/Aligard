"""/api/check ki request body. Extra fields reject, lengths capped (size limit router mein bhi hai)."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

Url = Annotated[str, StringConstraints(strip_whitespace=True, max_length=2048)]
Subject = Annotated[str, StringConstraints(max_length=500)]
Sender = Annotated[str, StringConstraints(max_length=320)]
Text = Annotated[str, StringConstraints(max_length=50_000)]


class CheckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["link", "message"]
    url: Url = ""
    subject: Subject = ""
    sender: Sender = ""
    text: Text = ""

    @model_validator(mode="after")
    def _need_content(self):
        if self.kind == "link" and not self.url:
            raise ValueError("Link likhna zaroori hai")
        if self.kind == "message" and not (self.text.strip() or self.subject.strip()):
            raise ValueError("Message ka text ya subject zaroori hai")
        return self
