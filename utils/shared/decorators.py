import time
from functools import wraps


class CustomDecorators:
    """Calculate the time taken to execute a function"""

    total_time = 0

    @staticmethod
    def measure_execution_time(func):
        """Measure the time taken to execute a function"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            execution_time = end_time - start_time
            CustomDecorators.total_time += execution_time
            # print(f"Execution time for {func.__name__}: {execution_time:.4f} seconds")
            return result
        return wrapper

    @classmethod
    def print_total_time(cls, message="Total execution time:"):
        """Print the total time taken to execute all functions"""
        hours, minutes, seconds = cls.format_time(cls.total_time)
        print(f"\n{message} {hours} hours, {minutes} minutes and {seconds} seconds")
        

    @staticmethod
    def format_time(time_in_seconds):
        """Format the time in seconds to hours, minutes and seconds"""
        time_in_seconds=round(time_in_seconds)
        hours, remainder = divmod(time_in_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return hours, minutes, seconds

    @classmethod
    def reset_total_time(cls):
        """Reset the total time to 0"""
        # global total_time
        cls.total_time = 0
