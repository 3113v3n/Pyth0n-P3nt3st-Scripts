import time
from functools import wraps
from .loader import Loader
# from loader import Loader


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

        def format_unit(unit:int, label:str):
            """Format label accordingly
            Args:
                unit:  time measurement
                label: [minutes,seconds,hours]
            """
            if unit == 1:
                return f"{unit} {label}"
            else:
                return f"{unit} {label}s"

        time_text = ""

        if seconds and not (minutes or hours):
            time_text = format_unit(seconds, "second")
        elif seconds and minutes and not (hours):
            time_text = f"{format_unit(minutes, "minute")} and {format_unit(seconds, "second")}."
        elif minutes and not (hours or seconds):
            time_text = format_unit(minutes, "minute")
        elif hours and not (minutes or seconds):
            time_text = format_unit(hours, "hour")
        elif hours and minutes and not seconds:
            time_text = f"{format_unit(hours, "hour")} and {format_unit(minutes, "minute")}"
        elif hours and seconds and not minutes:
            time_text = f"{format_unit(hours, "hour")} and {format_unit(seconds, "second")}."
        else:
            time_text = f"{format_unit(hours, "hour")}, {format_unit(minutes, "minute")} and {format_unit(seconds, "second")}"

        #print(f"{hours} hours:{minutes} minutes:{seconds} seconds")

        print(f"\n{message} {time_text}")

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


if __name__ == "__main__":
    decorator = CustomDecorators()

    decorator.print_total_time()
