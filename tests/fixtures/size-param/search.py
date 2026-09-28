@router.get("/search")
async def search(q: str, max_results: int = Query(20, ge=1)):
    return await repo.search(q, max_results)
