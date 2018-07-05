# How Turbinia Works
## General
This page contains some of the details on the internals of how Turbinia works.

## Tasks
A Task is the smallest discrete unit of schedulable work.  Tasks are scheduled
and executed on remote Workers.  A Task can generate more Evidence that is
returned back to the Turbinia server for possible further processing.

## Jobs
A Job is a larger unit of work that creates one or more Tasks to process that
work.  A Job can either create a single Task, or it can break up that work and
create multiple Tasks.  Sometimes these terms are used interchangeably (though
we mostly talk about things in terms of Tasks) because in most cases a Job will
just create a single Task.

## Workers
Workers are independent processes that run either in Cloud GCE instances or on
local machines.  They run continuously and wait for new Tasks to be scheduled.
When a new Task is scheduled, a pseudo-random worker will pick up the Task and
execute it.  After the Task is complete (successfully or not), the Worker will
return the status, any error logs and results.

## Evidence 
Evidence can be anything that Turbinia can process.  Examples include disk
images, cloud disks, Plaso files, strings files, etc.  When you make a request
to Turbinia only the metadata for the evidence is passed into the request, but
it contains pointers to where the data is.

### New Evidence
If you want to create a new Evidence type, they are simple Python objects in
[evidence.py](https://github.com/google/turbinia/blob/master/turbinia/evidence.py).
You can use object inheritance (e.g. an EncryptedDisk is a subclass of a
RawDisk) if you have multiple related Evidence types.  Each Evidence object also
can have a pre- and post-processor that will run on the Worker node just before
a Task is executed in order to prepare that piece of Evidence for the Task.
This can be used to do things like attach a Cloud Persistent Disk or mount a
local disk.

### Copyable Evidence
Some types of Evidence can be marked as "copyable".  What that means is that
this kind of Evidence can be copied around as needed (either to make it
available for a new Task to use it, or to copy it off of a Worker after the Task
has completed.  This is handled transparently by the Output Manager when it is
configured.  An example of this is the `PlasoFile` Evidence type.  Right now the
only storage that the Output Manager supports is Google Cloud Storage.  If
Evidence is not copyable (like a RawDisk) and not a Cloud Evidence type (as
denoted by the `cloud_only` attribute), then you will need to have a shared disk
that is available to all Workers.

## Task Manager
The Task Manager Acts as a broker between the clients and workers
and handles management of Evidence, Jobs, Tasks and Workers

## Task manager flow
Tasks are configured to "listen" for specific Evidence types, and if the Task
Manager sees a new piece of Evidence (either from a new Turbinia request, or
because another Task generated a new piece of Evidence), and there is a Task
that configured to run for that type of Evidence, then the Task Mananger will
schedule a new Task for it.
