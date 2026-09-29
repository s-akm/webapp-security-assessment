from fastapi import APIRouter, Depends, HTTPException

router = APIRouter()


@router.delete(
    "/{item_id}",
    status_code=204,
)
async def delete_item(
    item=Depends(get_item_from_path),
    user=Depends(get_current_user),
):
    await repo.delete(item)


@router.put("/{item_id}")
async def update_item(
    item=Depends(get_item_from_path),
    user=Depends(get_current_user),
):
    if item.owner_id != user.id:
        raise HTTPException(status_code=403)
    await repo.update(item)
