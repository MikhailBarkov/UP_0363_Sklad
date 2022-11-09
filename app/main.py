import uvicorn

from . import view
from .app import app


if __name__ == '__main__':
    uvicorn.run(app)
