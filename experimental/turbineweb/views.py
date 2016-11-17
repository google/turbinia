"""This module implements HTTP request handlers for the application."""

from flask import Blueprint
from flask import redirect
from flask import render_template

from models import Inventory
from models import Job
from models import db_session

# Register flask blueprint
turbineweb_views = Blueprint(u'turbineweb_views', __name__)


@turbineweb_views.route('/')
def inventory():
  items = Inventory.query.order_by(Inventory.updated_at.desc()).all()
  return render_template('inventory.html', items=items)


@turbineweb_views.route('/items/<int:item_id>')
def inventory_item(item_id):
  item = Inventory.query.get(item_id)
  return render_template('item.html', item=item)


@turbineweb_views.route('/tasks/item/<int:item_id>/<job_type>')
def run(item_id, job_type):
  inv_item = Inventory.query.get(item_id)

  if inv_item.status == 'pending':
    return 'ERROR: Not ready'

  if inv_item.has_active_jobs(job_type=job_type):
    return 'ERROR: I already have an active job of that type'

  job = Job(job_type=job_type)
  job.set_status('queued')
  inv_item.set_status('active')
  inv_item.jobs.append(job)
  db_session.commit()
  job.run()
  return redirect('/items/{0}'.format(inv_item.id))
