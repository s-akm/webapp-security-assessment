@app.get("/profile")
def profile(user = Depends(get_current_user)):
    return user

@app.post("/reports")
def reports():
    return []

@bp.route("/admin/stats")
@login_required
def stats():
    return {}
