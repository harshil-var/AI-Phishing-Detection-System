from pydantic import BaseModel, Field

class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Security query or question")

class ChatResponse(BaseModel):
    allowed: bool
    response: str
    topic_blocked: bool
