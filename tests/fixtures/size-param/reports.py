@router.get("/reports")
async def reports(max_results: int = Query(20, ge=1, le=200)):
    return await repo.reports(max_results)
