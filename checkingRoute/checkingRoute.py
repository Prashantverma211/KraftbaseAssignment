from fastapi import APIRouter


router = APIRouter(
    tags=["User Routes"]
)


@router.get("/check")
def get():
     return {"msg":"Hellow from check custom route"}
