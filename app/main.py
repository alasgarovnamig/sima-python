from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.api import sima_api

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["DELETE", "GET", "POST", "PUT"],
    allow_headers=["*"],
)

app.include_router(sima_api.router,prefix="/sima")