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
 * Retrieves a record.
 *
 * @example
 * gcloud beta functions call gettask \
 *     --data '{"kind":"Task","id":"abcd1234"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.kind The Datastore kind of the data to retrieve, e.g. "TurbiniaTask".
 * @param {string} req.body.id Id of task to retrieve
 * @param {object} res Cloud Function response context.
 */
exports.gettask = function gettask (req, res) {
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }
  if (!req.body.id) {
    throw new Error('Id parameter not provided in request.');
  }

  return datastore.get(id)
    .then(([entity]) => {
      // The get operation will not fail for a non-existent entity, it just
      // returns null.
      if (!entity) {
        throw new Error(`No entity found for id ${id.path.join('/')}.`);
      }

      res.status(200).send(entity);
    })
    .catch((err) => {
      console.error(err);
      res.status(500).send(err);
      return Promise.reject(err);
    });
};

/**
 * Retrieves recent Turbinia Task state records from Datastore.
 *
 * @example
 * gcloud beta functions call getrecenttasks --data \
 *     '{"kind":"TurbiniaTask","start":"1990-01-01T00:00:00z"}'
 *
 * @param {object} req Cloud Function request context.
 * @param {object} req.body The request body.
 * @param {string} req.body.key Key at which to retrieve the data, e.g. "sampletask1".
 * @param {object} res Cloud Function response context.
 */
exports.getrecenttasks = function getrecenttasks (req, res) {
  if (!req.body.kind) {
    throw new Error('Kind parameter not provided in request.');
  }
  if (!req.body.start) {
    throw new Error('Start parameter not provided in request.');
  }

  var start;
  try {
    start = new Date(req.body.start)
  } catch(err) {
    throw new Error('Could not convert start parameter into Date object')
  }

  const query = datastore.createQuery(req.body.kind)
    .filter('last_update', '>=', start)
    .order('last_update', {descending: true }
    );

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
