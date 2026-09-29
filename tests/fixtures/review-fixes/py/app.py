import pickle, yaml, random, jwt
from fastapi import FastAPI, Depends
app = FastAPI()
@app.get("/items")
def items(db=Depends(get_db)):
    return db.query(Item).all()
@app.post("/load")
def load(request):
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.body)
    token = ''.join(random.choice('abc') for _ in range(20))
    cursor.execute(query)
    claims = jwt.decode(request.token, KEY, algorithms=["HS256"])
    raw = jwt.decode(request.token, options={"verify_signature": False})
    return claims
def f():
    try:
        g()
    except Exception:
        pass
