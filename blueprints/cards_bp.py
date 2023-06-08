from flask import Blueprint
from init import db
from models.card import Card, CardSchema
from flask_jwt_extended import jwt_required
from blueprints.auth_bp import admin_required

cards_bp = Blueprint('cards', __name__)

@cards_bp.route('/cards')
@jwt_required()
def all_cards():
    admin_required()
    # select * from cards;
    ## in sqlalchemy language:
    stmt = db.select(Card).order_by(Card.status.desc())
    cards = db.session.scalars(stmt).all()
    return CardSchema(many=True).dump(cards)