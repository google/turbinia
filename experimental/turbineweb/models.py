"""This module implements the models for the inventory system."""

from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import DateTime
from sqlalchemy import func
from sqlalchemy import Unicode
from sqlalchemy import UnicodeText
from sqlalchemy import ForeignKey
from sqlalchemy import Boolean
from sqlalchemy.ext.declarative import as_declarative
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import relationship


# The database session
engine = None
session_maker = sessionmaker()
db_session = scoped_session(session_maker)


def configure_engine(url):
    """Configure and setup the database session."""
    global engine, session_maker, db_session
    engine = create_engine(url)
    db_session.remove()
    session_maker.configure(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize the database based on the implemented models. This will setup
    the database on the first run.
    """
    BaseModel.metadata.create_all(bind=engine)
    BaseModel.query = db_session.query_property()


def drop_all():
    """Drop all tables in the database."""
    BaseModel.metadata.drop_all(bind=engine)


@as_declarative()
class BaseModel(object):
    """Base class used for database models. 
    Common model fields to all models classes that subclass it.
    """

    @declared_attr
    def __tablename__(self):
        return self.__name__.lower()
    id = Column(Integer, primary_key=True)
    status = Column(Unicode(255), default=u'unknown')
    created_at = Column(DateTime(), default=func.now())
    updated_at = Column(DateTime(), default=func.now(), onupdate=func.now())

    @classmethod
    def get_or_create(cls, **kwargs):
        """Get or create a database object.
        Returns:
            A model instance.
        """
        instance = cls.query.filter_by(**kwargs).first()
        if not instance:
            instance = cls(**kwargs)
            db_session.add(instance)
            db_session.commit()
        return instance

    def set_status(self, status):
        self.status = status
        db_session.add(self)
        db_session.commit()


class Inventory(BaseModel):
    """Implements the Inventory model."""
    name = Column(Unicode(255))
    description = Column(UnicodeText())
    uuid = Column(Unicode(255))
    src_data_loc = Column(Unicode(255))
    dst_data_loc = Column(Unicode(255))
    src_data_size = Column(Unicode(255))
    jobs = relationship(u'Job', backref=u'job')

    def __init__(
            self, name, description, uuid, src_data_loc, dst_data_loc,
            src_data_size):
        super(Inventory, self).__init__()
        self.name = name
        self.description = description
        self.uuid = uuid
        self.src_data_loc = src_data_loc
        self.dst_data_loc = dst_data_loc
        self.src_data_size = src_data_size

    def has_active_jobs(self, job_type=None):
        """Determine if the Inventory item has active jobs.
            Args:
                job_type: Name of the job.
            Returns:
                List of jobs (instances of turbineweb.models.Job)
        """
        if job_type:
            active_jobs = Job.query.filter(
                Job.inventory_id == self.id, Job.status != 'done',
                Job.status != 'error', Job.job_type == job_type).all()
        else:
            active_jobs = Job.query.filter(
                Job.inventory_id == self.id, Job.status != 'done',
                Job.status != 'error').all()
        return active_jobs


class Job(BaseModel):
    """Implements the Job model.
    A Job is the mapping between an Inventory item and a result of
    running the workload on the cluster.
    """
    job_type = Column(Unicode(255))
    uuid = Column(Unicode(255))
    version = Column(Unicode(255))
    processing_time = Column(Unicode(255))
    result = Column(UnicodeText())
    error = Column(Boolean(), default=False)
    inventory_id = Column(Integer, ForeignKey(u'inventory.id'))

    def __init__(self, job_type, uuid=None):
        super(Job, self).__init__()
        self.job_type = job_type
        if not uuid:
            self.uuid = uuid4().hex

    def run(self):
        """Create a job to be processed by the backend cluster.
        Returns:
            A innventory item (instance of turbineweb.models.Inventory)
        """
        # TODO: Start turbinia job
        inv_item = Inventory.query.get(self.inventory_id)
        return inv_item

