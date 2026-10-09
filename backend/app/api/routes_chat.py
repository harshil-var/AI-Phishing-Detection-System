from fastapi import APIRouter, HTTPException, status
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.chatbot_service import get_chatbot_response

router = APIRouter(prefix="", tags=["Security Chatbot"])

@router.post("/chat", response_model=ChatResponse, summary="Query LLM Security Assistant")
def security_chat(payload: ChatRequest):
    """
    Query the guarded LLM Security Assistant for phishing and cybersecurity guidance.
    Enforces strict topic boundary guard.
    """
    if not payload.prompt or not payload.prompt.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Prompt cannot be empty."
        )
    
    result = get_chatbot_response(payload.prompt)
    return result
