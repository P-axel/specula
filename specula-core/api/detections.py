from fastapi import APIRouter, Query, Depends, HTTPException
from typing import Optional, List, Any, Dict
from providers.provider_manager import ProviderManager
from pydantic import BaseModel, Field

router = APIRouter(tags=["detections"])

class Detection(BaseModel):
    id: str
    source: str
    # On rend le message optionnel pour éviter les ResponseValidationError (500)
    message: Optional[str] = Field(None, description="Description ou titre de la détection")
    timestamp: str

    class Config:
        # Permet d'accepter d'autres champs sans crash (comme 'title', 'severity', etc.)
        extra = "allow"

def get_provider_manager() -> ProviderManager:
    return ProviderManager()

@router.get("/detections", response_model=List[Detection])
def list_detections(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: Optional[str] = Query(None),
    provider_manager: ProviderManager = Depends(get_provider_manager),
) -> List[Any]:
    try:
        results = provider_manager.list_detections(
            source=source,
            limit=limit,
            offset=offset,
        )
        
        # Normalisation de secours : si 'message' est absent mais 'title' est là
        normalized_results = []
        for det in results:
            if isinstance(det, dict):
                if not det.get("message"):
                    det["message"] = det.get("title") or det.get("name") or "No description available"
                normalized_results.append(det)
            else:
                normalized_results.append(det)
                
        return normalized_results

    except Exception as e:
        # On log l'erreur réelle en console pour le debug interne
        print(f"DEBUG Error in list_detections: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch detections: {str(e)}")