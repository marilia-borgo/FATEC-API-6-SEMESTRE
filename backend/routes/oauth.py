import secrets
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.oauth_models import OAuth2Client
from backend.core.schemas import OAuthClientCreate, OAuthClientCreatedResponse
from backend.database import get_session
from backend.security import get_password_hash

router = APIRouter(prefix='/oauth', tags=['oauth'])
T_Session = Annotated[AsyncSession, Depends(get_session)]


@router.post(
    '/clients',
    status_code=HTTPStatus.CREATED,
    response_model=OAuthClientCreatedResponse,
)
async def register_client(body: OAuthClientCreate, session: T_Session):
    client_id = secrets.token_hex(24)
    plaintext_secret = secrets.token_urlsafe(32)

    client = OAuth2Client(client_id=client_id)
    client.client_secret = get_password_hash(plaintext_secret)
    client.set_client_metadata({
        'client_name': body.client_name,
        'redirect_uris': body.redirect_uris,
        'scope': ' '.join(body.allowed_scopes),
    })

    session.add(client)
    await session.commit()

    return OAuthClientCreatedResponse(
        client_id=client_id,
        client_secret=plaintext_secret,
    )
