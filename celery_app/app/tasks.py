from celery import Celery, Task
import time
import os

# URL to connect to broker
broker_url = os.environ['BROKER']

# Create Celery application
# Queues created by Celery are persistent by default. This means that the broker will write messages to disk to ensure that the tasks will be executed even if the broker is restarted.

application = Celery('tasks', broker=broker_url)


class TaskError(Exception):
    """Custom exception for handling task errors"""
    pass


class AppBaseTask(Task):
    """Base Task

    The base Task class can be used to define
    shared behaviour between tasks.

    """

    abstract = True

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        # TODO: log out here
        super(AppBaseTask, self).on_retry(exc, task_id, args, kwargs, einfo)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # TODO: log out here
        super(AppBaseTask, self).on_failure(exc, task_id, args, kwargs, einfo)

@application.task(base=AppBaseTask, bind=True, max_retries=3, soft_time_limit=50)
def do_task(self):
    """Performs simple geoprocessing task.

    Failed tasks are retried x times by the Task classes on_retry method.
    When tasks fail completely they are handled by the Task classes on_failure method

    Args:
        self: instance of the Task
        x: integer
        y: integer

    Raises:
        TaskError: failed tasked are handled by the parent task class.

    Returns:
        None
    """
    print("something happening")
    time.sleep(5)
    print("something happened")