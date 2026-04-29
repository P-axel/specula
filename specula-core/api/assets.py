import logging

from fastapi import APIRouter, HTTPException

from api.dependencies import assets_service

router = APIRouter(tags=["assets"])
logger = logging.getLogger(__name__)


@router.get("/assets")
def list_assets() -> list[dict]:
    try:
        assets = assets_service.list_assets()
        return [asset.to_dict() for asset in assets]
    except Exception as exc:
        logger.warning("Wazuh indisponible, /assets retourne liste vide: %s", exc)
        return []


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str) -> dict:
    try:
        asset = assets_service.get_asset(asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset.to_dict()
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Wazuh indisponible, /assets/%s introuvable: %s", asset_id, exc)
        raise HTTPException(status_code=404, detail="Asset not found")