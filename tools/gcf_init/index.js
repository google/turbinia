/**
 * Copyright 2017, Google, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

// Global
const Datastore = require('@google-cloud/datastore');
// Instantiates a client
const datastore = Datastore();
const turbiniaKind = 'TurbiniaTask'


/**
 * Retrieves tasks given a start time, task Id or Request Id.
 *
 * @example
 * gcloud beta functions call gettasks \
 *     --data '{"instance": "turbinia-prod", "kind":"TurbiniaTask",
 *              "task_id":"abcd1234"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.kind The kind of Datastore Entity to request
 * @param {string} req.body.start_time A date string in ISO 8601 format of the
 *                 beginning of the time window to query for
 * @param {string} req.body.task_id Id of task to retrieve
 * @param {string} req.body.request_id of tasks to retrieve
 * @param {object} res Cloud Function response context.
 */
exports.gettasks = function gettasks(req, res) {
  if (!req.body.instance) {
    throw new Error('Instance parameter not provided in request.');
  }
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }

  var query;
  var start_time;

  // Note: If you change any of these filter properties, you must also update
  // the tools/gcf_init/index.yaml and re-run tools/gcf_init/deploy_gcf.py
  if (req.body.task_id) {
    console.log('Getting Turbinia Tasks by Task Id: ' + req.body.task_id);
    query = datastore.createQuery(req.body.kind)
                .filter('instance', '=', req.body.instance)
                .filter('id', '=', req.body.task_id)
                .order('last_update', {descending: true});
  } else if (req.body.request_id) {
    console.log('Getting Turbinia Tasks by Request Id: ' + req.body.request_id);
    query = datastore.createQuery(req.body.kind)
                .filter('instance', '=', req.body.instance)
                .filter('request_id', '=', req.body.request_id)
                .order('last_update', {descending: true});
  } else if (req.body.start_time) {
    try {
      start_time = new Date(req.body.start_time)
    } catch (err) {
      throw new Error('Could not convert start_time parameter into Date object')
    }
    console.log('Getting Turbinia Tasks by last_updated range: ' + start_time);
    query = datastore.createQuery(req.body.kind)
                .filter('instance', '=', req.body.instance)
                .filter('last_update', '>=', start_time)
                .order('last_update', {descending: true});
  } else {
    console.log('Getting open Turbinia Tasks.');
    query = datastore.createQuery(req.body.kind)
                .filter('instance', '=', req.body.instance)
                .filter('successful', '=', null)
                .order('last_update', {descending: true});
  }

  return datastore.runQuery(query)
      .then((results) => {
        // Task entities found.
        const tasks = results[0];

        console.log('Turbinia Tasks:');
        tasks.forEach((task) => console.log(task));
        res.status(200).send(results);
      })
      .catch((err) => {
        console.error('Error in runQuery' + err);
        res.status(500).send(err);
        return Promise.reject(err);
      });
};

/**
 * Retrieves recent Turbinia Task state records from Datastore.
 *
 * @example
 * gcloud beta functions call getrecenttasks --data \
 *     '{"kind":"TurbiniaTask","start_time":"1990-01-01T00:00:00z"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.instance The Turbinia instance
 * @param {string} req.body.kind The kind of Datastore Entity to request
 * @param {string} req.body.start_time A date string in ISO 8601 format of the
 *                 beginning of the time window to query for
 * @param {object} res Cloud Function response context.
 */
exports.getrecenttasks = function getrecenttasks(req, res) {
  if (!req.body.instance) {
    throw new Error('Instance parameter not provided in request.');
  }
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }
  if (!req.body.start_time) {
    throw new Error('Start_time parameter not provided in request.');
  }

  var start_time;
  try {
    start_time = new Date(req.body.start_time)
  } catch (err) {
    throw new Error('Could not convert start_time parameter into Date object')
  }

  const query = datastore.createQuery(req.body.kind)
                    .filter('instance', '=', req.body.instance)
                    .filter('last_update', '>=', start_time)
                    .order('last_update', {descending: true});

  console.log(query);
  return datastore.runQuery(query)
      .then((results) => {
        // Task entities found.
        const tasks = results[0];

        console.log('Turbinia Tasks:');
        tasks.forEach((task) => console.log(task));
        res.status(200).send(results);
      })
      .catch((err) => {
        console.error(err);
        res.status(500).send(err);
        return Promise.reject(err);
      });
};

/**
 * Closes tasks based on the Request Id.
 *
 * @example
 * gcloud beta functions call closetasksbyrequestid \
 *     --data '{"instance": "turbinia-prod", "kind":"TurbiniaTask",
 *              "request_id":"abcd1234"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.kind The kind of Datastore Entity to request
 * @param {string} req.body.request_id of tasks to retrieve
 * @param {object} res Cloud Function response context.
 */
exports.closetasksbyrequestid = function closetasksbyrequestid(req, res) {
  if (!req.body.instance) {
    throw new Error('Instance parameter not provided in request.');
  }
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }
  if (!req.body.request_id) {
    throw new Error('request_id parameter not provided in request.');
  }

  if (req.body.request_id) {
    console.log('Getting Turbinia Tasks by Request Id: ' + req.body.request_id);
    var query = datastore.createQuery(req.body.kind)
      .filter('instance', '=', req.body.instance)
      .filter('request_id', '=', req.body.request_id)
      .filter('successful', '=', null)
      .order('last_update', {descending: true });

    return datastore.runQuery(query)
      .then((results) => {
          // Task entities found.
          const tasks = results[0];
          var uncompleted_tasks = [];
          tasks.forEach((task) => {
              console.log(task);
              uncompleted_tasks.push(task.id);
              });
          return uncompleted_tasks;
          })
      .then((uncompleted_tasks) => {
          uncompleted_tasks.forEach((id) => {
              module.exports.closetask(id);
              });
          return uncompleted_tasks;
          })
      .then((uncompleted_tasks) => {
          res.status(200).send(uncompleted_tasks);
          })
      .catch((err) => {
          console.error('Error in runQuery' + err);
          res.status(500).send(err);
          return Promise.reject(err);
          });
  }
};

/**
 * Closes a task based on the Task ID.
 *
 * @example
 * gcloud beta functions call closetaskbytaskid \
 *     --data '{"instance": "turbinia-prod", "kind":"TurbiniaTask",
 *              "task_id":"abcd1234"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.kind The kind of Datastore Entity to request
 * @param {string} req.body.task_id of task to retrieve
 * @param {object} res Cloud Function response context.
 */
exports.closetaskbytaskid = function closetaskbytaskid(req, res) {
  if (!req.body.instance) {
    throw new Error('Instance parameter not provided in request.');
  }
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }
  if (!req.body.task_id) {
    throw new Error('task_id parameter not provided in request.');
  }
  
  console.log('Getting Turbinia Task by Task Id: ' + req.body.task_id);
  const query = datastore
    .createQuery(req.body.kind)
    .filter('instance', '=', req.body.instance)
    .filter('__key__', '=', datastore.key([turbiniaKind, req.body.task_id]))
    .filter('successful', '=', null);

  return datastore.runQuery(query)
    .then((results) => {
        // Task entity found
        const tasks = results[0];
        const task = tasks[0];
        if (tasks) {
          console.log(tasks);
          module.exports.closetask(task.id);
        }
        return task;
        })
    .then((task) => {
        const request_id = task.request_id
        const task_id = task.id
        res.status(200).send({'request_id': request_id, 'task_id': task_id});
        })
    .catch((err) => {
        console.error('Error in runQuery' + err);
        res.status(500).send(err);
        return Promise.reject(err);
        });
};

exports.closetask = function closetask(id) {
  if (!id) {
    throw new Error('Entity Key not provided in request.');
  }
  const transaction = datastore.transaction();
  const taskKey = datastore.key([turbiniaKind, id]);
  console.log("Preparing transaction.");
  transaction
    .run()
    .then(() => transaction.get(taskKey))
    .then(results => {
      const taskEntity = results[0];
      taskEntity.successful = false;
      var updatedEntity = {
        key: taskKey,
        data: taskEntity,
      };
      transaction.save(updatedEntity);

      console.log("Committing transaction: %o", updatedEntity);
      transaction.commit()
        .then(() => {
          console.log("Entity successfully saved.");
          return updatedEntity;
        })
        .catch(err => {
            console.error("Rolling back - Error in transaction (Failure)")
            console.error(err);
            transaction.rollback();
        });
    })
    .catch((err) => {
      console.error("Rolling back - Error in transaction (Other Reasons)")
      console.error(err);
      transaction.rollback();
    });
};

