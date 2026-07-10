from pydantic import BaseModel, Field


class SecretWriteRequest(BaseModel):
    value: str = Field(min_length=1)


class SecretResponse(BaseModel):
    path: str
    value: str


class SecretListResponse(BaseModel):
    paths: list[str]
