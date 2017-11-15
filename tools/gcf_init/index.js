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

const Datastore = require('@google-cloud/datastore');

// Instantiates a client
const datastore = Datastore();


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
exports.gettasks = function gettasks (req, res) {
  if (!req.body.instance) {
    throw new Error('Instance parameter not provided in request.');
  }
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }

  var query;
  var start_time;
  if (req.body.task_id) {
    console.log('Getting Turbinia Tasks by Task Id');
    query = datastore.createQuery(req.body.kind)
      .filter('instance', '=', req.body.instance)
      .filter('id', '=', req.body.task_id)
      .order('last_update', {descending: true }
      );
  } else if (req.body.request_id) {
    console.log('Getting Turbinia Tasks by Request Id');
    query = datastore.createQuery(req.body.kind)
      .filter('instance', '=', req.body.instance)
      .filter('request_id', '=', req.body.request_id)
      .order('last_update', {descending: true }
      );
  } else if (req.body.start_time) {
    console.log('Getting Turbinia Tasks by last_updated range');
    try {
      start_time = new Date(req.body.start_time)
    } catch(err) {
      throw new Error('Could not convert start_time parameter into Date object')
    }
    query = datastore.createQuery(req.body.kind)
      .filter('instance', '=', req.body.instance)
      .filter('last_update', '>=', start_time)
      .order('last_update', {descending: true }
      );
  } else {
    console.log('Getting open Turbinia Tasks.');
    query = datastore.createQuery(req.body.kind)
      .filter('instance', '=', req.body.instance)
      .filter('successful', '!=', true)
      .filter('successful', '!=', false)
      .order('last_update', {descending: true }
      );
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
exports.getrecenttasks = function getrecenttasks (req, res) {
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
  } catch(err) {
    throw new Error('Could not convert start_time parameter into Date object')
  }

  const query = datastore.createQuery(req.body.kind)
    .filter('instance', '=', req.body.instance)
    .filter('last_update', '>=', start_time)
    .order('last_update', {descending: true }
    );

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
