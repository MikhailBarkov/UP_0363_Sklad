import sqlalchemy as sa
from sqlalchemy.orm import declarative_base

from datetime import datetime


Base = declarative_base()


class Product(Base):
    __tablename__ = 'products'

    id = sa.Column(sa.Integer, primary_key=True)

    storage_units_count = sa.Column(sa.Integer)
    # номер таможенной декларации
    order_number = sa.Column(sa.String(22), unique=True)
    price = sa.Column(sa.Numeric(10, 2))

    created = sa.Column(sa.DateTime, default=datetime.now())

    user = sa.Column(sa.Integer, sa.ForeignKey('users.id'))
    material = sa.Column(sa.Integer, sa.ForeignKey('materials.id'))
    provider = sa.Column(sa.Integer, sa.ForeignKey('providers.id'))

    def __repr__(self):
        return f'<Product id: {self.id}>'


class Material(Base):
    __tablename__ = 'materials'

    id = sa.Column(sa.Integer, primary_key=True)

    name = sa.Column(sa.String(255), unique=True)
    class_code = sa.Column(sa.Integer)
    group_code = sa.Column(sa.Integer)

    uom = sa.Column(sa.Integer, sa.ForeignKey('uoms.id'))

    def __repr__(self):
        return f'<Material id: {self.id}, name: {self.name}>'


class UOM(Base):
    __tablename__ = 'uoms'

    id = sa.Column(sa.Integer, primary_key=True)

    name = sa.Column(sa.String(255), unique=True)

    def __repr__(self):
        return f'<UOM id: {self.id}, name: {self.name}>'


class Provider(Base):
    __tablename__ = 'providers'

    id = sa.Column(sa.Integer, primary_key=True)

    name = sa.Column(sa.String(255), unique=True)
    inn = sa.Column(sa.String(10), unique=True)
    provider_addres = sa.Column(sa.String(255))
    bank_addres = sa.Column(sa.String(255))
    bank_account = sa.Column(sa.String(20))

    def __repr__(self):
        return f'<Provider id: {self.id}, name: {self.name}>'


class User(Base):
    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)

    username = sa.Column(sa.String(255), unique=True)
    access = sa.Column(sa.Integer)
    password_hash = sa.Column(sa.String(60))
    salt = sa.Column(sa.String(8))

    def __repr__(self):
        return f'<User id: {self.id}, name {self.username}>'
