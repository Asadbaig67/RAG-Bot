# Importing required libraries for scheduling
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta, time
from apscheduler.triggers.cron import CronTrigger
import pytz
from app import sendTranscript
from apscheduler.schedulers.blocking import BlockingScheduler

# This function schedules the email to be sent daily
def schedule_transcript():
    print("[LOG] schedule_transcript function called!")  

    """ Function to schedule the sendTranscript job """
    #scheduler = BackgroundScheduler()
    scheduler = BlockingScheduler()

    # Get current local time
    local_now = datetime.now()
    
    # Convert local time to UTC
    utc_now = local_now.astimezone(pytz.utc)
    print(f"[LOG] Current UTC time: {utc_now.time()}") # Log statement
    
    # If current UTC time is before 6:00am, set the scheduled time for today at 6:00am UTC.
    # Otherwise, set it for 6:00am UTC of the next day.
    if utc_now.time() >= time(23, 15):
        print('log')
        utc_now += timedelta(days=1)

    # Define the cron trigger for 7:00 AM UTC
    trigger = CronTrigger(hour=23, minute=15, second=0, timezone='UTC')
    print(f"trigger: {trigger}")
    # Schedule the job with the specified trigger
    scheduler.add_job(func=sendTranscript, trigger=trigger)
    scheduler.start()


schedule_transcript()
