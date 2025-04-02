import time
from functools import wraps
from .loader import Loader
#from loader import Loader



class CustomDecorators:
    """Calculate the time taken to execute a function"""

    total_time = 0
    _loader_active = False

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
    def with_loader(cls,
                    desc: str,
                    end: str,
                    spinner_type: str = "dots",
                    timer: int = 10):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
               # Start loader only if it is not already active
                if not cls._loader_active:
                    loader = Loader(
                        desc=desc,
                        end=end,
                        spinner_type=spinner_type,
                        timer=timer
                    )
                    cls._loader_active = True
                    try:
                        loader.start()  # Start the loader
                        result = func(*args, **kwargs)  # Execute the function
                        return result
                    finally:
                        loader.stop()  # Stop the loader
                        cls._loader_active = False
                else:
                    # Execute function without starting the loader again
                    return func(*args, **kwargs)
            return wrapper
        return decorator

    @classmethod
    def print_total_time(cls, message="Total execution time:"):
        """Print the total time taken to execute all functions"""
        hours, minutes, seconds = cls.format_time(cls.total_time)
        print(f"\n{message} {hours} hours, {minutes} minutes and {seconds} seconds")

    @staticmethod
    def format_time(time_in_seconds):
        """Format the time in seconds to hours, minutes and seconds"""
        time_in_seconds = round(time_in_seconds)
        hours, remainder = divmod(time_in_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return hours, minutes, seconds

    @classmethod
    def reset_total_time(cls):
        """Reset the total time to 0"""
        # global total_time
        cls.total_time = 0

@CustomDecorators.with_loader(desc="Filtering Issues", end="Completed")
def filter_issues(data):
    # Your filtering logic here
    # Simulate processing time
    time.sleep(2)  # Simulate a delay for demonstration
    return "Filtered Data"

@CustomDecorators.with_loader(desc="Categorizing Issues", end="Completed")
def categorize_issues(data):
    # Your categorizing logic here
    time.sleep(2)  # Simulate a delay for demonstration
    return "Categorized Data"

@CustomDecorators.with_loader(desc="Creating Summary Page", end="Completed")
def create_summary(data):
    # Your summary creation logic here
    time.sleep(2)  # Simulate a delay for demonstration
    return "Summary Created"

# Example of calling the functions in a loop
if __name__ == "__main__":
    for _ in range(3):
        filter_issues("data")
        categorize_issues("data")
        create_summary("data")
