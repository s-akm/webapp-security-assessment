from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/api/admin")
def admin(user = Depends(get_current_user)):     # ガードあり
    return {"ok": True}

@app.post("/api/report")
def report(email: str):                           # ガードなし
    send_mail(email)
    return {"ok": True}
