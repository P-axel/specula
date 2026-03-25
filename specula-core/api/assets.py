from fastapi import APIRouter, HTTPException

from api.dependencies import assets_service

router = APIRouter(tags=["assets"])


@router.get("/assets")
def list_assets() -> list[dict]:
    try:
        assets = assets_service.list_assets()
        return [asset.to_dict() for asset in assets]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"/assets failed: {exc}")


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
        raise HTTPException(status_code=500, detail=f"/assets/{{asset_id}} failed: {exc}")