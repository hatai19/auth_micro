import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth.router import auth_router
from dotenv import load_dotenv

app = FastAPI()

app.include_router(auth_router)

origins = [
    f"http://{os.getenv('HOST')}:{int(os.getenv('PORT'))}",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv('HOST'), port=int(os.getenv('PORT')))