from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
# maintain the same connection per thread
from sqlalchemy.pool import SingletonThreadPool

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Maker(Base):
    __tablename__ = 'maker'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
       }

class TransportationItem(Base):
    __tablename__ = 'transportation_item'

    id = Column(Integer, primary_key = True)
    make = Column(String(80), nullable = True)
    model = Column(String(80), nullable = False)
    year = Column(String(10), nullable = False)
    mileage = Column(Integer, nullable = False)
    trim = Column(String(80), nullable = True)
    vin =  Column(String(80), nullable = False)
    automatic = Column(Integer, nullable = True)
    description = Column(String(80), nullable = True)
    price = Column(String(8))
    maker_id = Column(Integer,ForeignKey('maker.id'))
    maker = relationship(Maker)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
           'id'         : self.id,
           'model'      : self.model,
           'year'       : self.year,
           'mileage'     : self.mileage,
           'trim'      : self.trim,
           'vin'       : self.vin,
           'automatic'    : self.automatic,
           'description'  : self.description,
           'price'        : self.price,
        }


engine = create_engine('sqlite:///catalog.sqlite',
poolclass=SingletonThreadPool)

Base.metadata.create_all(engine)